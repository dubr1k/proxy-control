//! The HTTPS client against a local TLS server (rustls, a throwaway CA made with `openssl` at
//! test time): status and header handling, size caps, per-hop redirect checks, timeouts.
//! Skipped when `openssl` is not installed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pc_host::net::{ClientOptions, HttpsClient, NetError, Redirects, Request, Roots};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl").args(args).current_dir(dir).output().map(|o| o.status.success()).unwrap_or(false)
}

/// (CA DER, leaf DER, leaf PKCS#8 key DER), or `None` without openssl.
fn certificates(dir: &Path) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
    let mut ca = vec!["req", "-x509"];
    ca.extend(ec);
    ca.extend(["-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=pc-host-test-ca"]);
    if !openssl(dir, &ca) {
        return None;
    }
    let mut csr = vec!["req"];
    csr.extend(ec);
    csr.extend(["-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost"]);
    std::fs::write(
        dir.join("ext.cnf"),
        "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n",
    )
    .ok()?;
    let ok = openssl(dir, &csr)
        && openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                "2",
                "-extfile",
                "ext.cnf",
            ],
        )
        && openssl(dir, &["x509", "-in", "ca.pem", "-outform", "der", "-out", "ca.der"])
        && openssl(dir, &["x509", "-in", "leaf.pem", "-outform", "der", "-out", "leaf.der"])
        && openssl(dir, &["pkcs8", "-topk8", "-nocrypt", "-in", "leaf.key", "-outform", "der", "-out", "leaf.key.der"]);
    if !ok {
        return None;
    }
    Some((
        std::fs::read(dir.join("ca.der")).ok()?,
        std::fs::read(dir.join("leaf.der")).ok()?,
        std::fs::read(dir.join("leaf.key.der")).ok()?,
    ))
}

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    host: String,
    user_agent: String,
    body: Vec<u8>,
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn header_value(head: &str, name: &str) -> String {
    head.lines()
        .find_map(|line| {
            line.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default()
}

fn serve(stream: TcpStream, config: Arc<rustls::ServerConfig>, port: u16, seen: Arc<Mutex<Vec<Seen>>>) {
    let connection = rustls::ServerConnection::new(config).unwrap();
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    let head_end = loop {
        match tls.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
        }
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let length: usize = header_value(&head, "content-length").parse().unwrap_or(0);
    while raw.len() < head_end + length {
        match tls.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
        }
    }
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();
    seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        host: header_value(&head, "host"),
        user_agent: header_value(&head, "user-agent"),
        body: raw[head_end..].to_vec(),
    });
    let (status, headers, body): (u16, Vec<(String, String)>, Vec<u8>) = match path.as_str() {
        "/ok" => (
            200,
            vec![
                ("docker-content-digest".into(), "sha256:abc".into()),
                ("x-dup".into(), "one".into()),
                ("x-dup".into(), "two".into()),
            ],
            b"hello".to_vec(),
        ),
        "/big" => (200, vec![], vec![b'b'; 1000]),
        "/missing" => (404, vec![], b"not found body".to_vec()),
        "/to-other-host" => (302, vec![("location".into(), format!("https://127.0.0.1:{port}/ok"))], vec![]),
        "/to-http" => (301, vec![("location".into(), format!("http://localhost:{port}/ok"))], vec![]),
        "/loop" => (302, vec![("location".into(), "/loop".into())], vec![]),
        "/no-location" => (302, vec![], vec![]),
        "/post" if method == "POST" => (303, vec![("location".into(), "/ok".into())], vec![]),
        "/stall" => {
            std::thread::sleep(Duration::from_secs(3));
            (200, vec![], b"late".to_vec())
        }
        other if other.starts_with("/chain/") => {
            let n: u32 = other["/chain/".len()..].parse().unwrap();
            if n == 0 {
                (200, vec![], b"done".to_vec())
            } else {
                (307, vec![("location".into(), format!("/chain/{}", n - 1))], vec![])
            }
        }
        _ => (500, vec![], vec![]),
    };
    let mut response = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.write_all(&body);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn start(leaf: Vec<u8>, key: Vec<u8>) -> Server {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (config, log) = (config.clone(), log.clone());
            std::thread::spawn(move || serve(stream, config, port, log));
        }
    });
    Server { port, seen }
}

fn setup() -> Option<(Scratch, Server, Vec<u8>)> {
    let dir = Scratch(std::env::temp_dir().join(format!("pc-host-tls-{}", pc_host::fs::token_hex::<8>())));
    std::fs::create_dir(&dir.0).unwrap();
    let Some((ca, leaf, key)) = certificates(&dir.0) else {
        eprintln!("openssl is not available; skipping");
        return None;
    };
    Some((dir, start(leaf, key), ca))
}

fn client(ca: &[u8], timeout: Duration) -> HttpsClient {
    HttpsClient::new(ClientOptions { roots: Roots::Der(vec![ca.to_vec()]), timeout, ..ClientOptions::default() })
        .unwrap()
}

const ALLOWED: &[&str] = &["localhost"];

#[test]
fn https_client_contract() {
    let Some((_dir, server, ca)) = setup() else { return };
    let client = client(&ca, Duration::from_secs(10));
    let base = format!("https://localhost:{}", server.port);

    // 200: body, title-cased headers (the last duplicate wins), the agent's User-Agent.
    let answer = client.get(&format!("{base}/ok"), ALLOWED, &[("Accept", "application/json")], 100).unwrap();
    assert_eq!((answer.status(), answer.body.as_slice()), (200, &b"hello"[..]));
    assert_eq!(answer.head.headers["Docker-Content-Digest"], "sha256:abc");
    assert_eq!(answer.head.headers["X-Dup"], "two");
    assert_eq!(answer.head.raw_headers.iter().filter(|(k, _)| k == "x-dup").count(), 2);
    let last = server.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.user_agent, "proxy-control-version-agent/1");
    assert_eq!(last.host, format!("localhost:{}", server.port));

    // A caller's User-Agent replaces the default.
    client.get(&format!("{base}/ok"), ALLOWED, &[("User-Agent", "custom/1")], 100).unwrap();
    assert_eq!(server.seen.lock().unwrap().last().unwrap().user_agent, "custom/1");

    // Non-2xx: status and headers, never the body.
    let missing = client.get(&format!("{base}/missing"), ALLOWED, &[], 100).unwrap();
    assert_eq!((missing.status(), missing.body.len()), (404, 0));

    // Size cap: exactly `maximum` is fine, one more byte is "too large".
    assert_eq!(client.get(&format!("{base}/big"), ALLOWED, &[], 1000).unwrap().body.len(), 1000);
    assert_eq!(client.get(&format!("{base}/big"), ALLOWED, &[], 999), Err(NetError::TooLarge));
    let mut sink = Vec::new();
    let head = client.download(&format!("{base}/big"), ALLOWED, &[], 5000, &mut sink).unwrap();
    assert_eq!((head.status, sink.len()), (200, 1000));
}

#[test]
fn redirects_are_checked_on_every_hop() {
    let Some((_dir, server, ca)) = setup() else { return };
    let client = client(&ca, Duration::from_secs(10));
    let base = format!("https://localhost:{}", server.port);

    let chained = client.get(&format!("{base}/chain/3"), ALLOWED, &[], 100).unwrap();
    assert_eq!((chained.status(), chained.body.as_slice()), (200, &b"done"[..]));
    assert_eq!(chained.head.final_url, format!("{base}/chain/0"));

    // Ten redirects are followed; the eleventh comes back as its status with no body.
    let looped = client.get(&format!("{base}/loop"), ALLOWED, &[], 100).unwrap();
    assert_eq!((looped.status(), looped.body.len()), (302, 0));
    let loops = server.seen.lock().unwrap().iter().filter(|s| s.path == "/loop").count();
    assert_eq!(loops, 11);

    let before = server.seen.lock().unwrap().len();
    assert_eq!(
        client.get(&format!("{base}/to-other-host"), ALLOWED, &[], 100),
        Err(NetError::RedirectLeftAllowedHosts)
    );
    assert_eq!(client.get(&format!("{base}/to-http"), ALLOWED, &[], 100), Err(NetError::RedirectLeftAllowedHosts));
    // The refused hops were never requested.
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), before + 2);
    assert!(seen.iter().all(|s| s.host.starts_with("localhost")));
    drop(seen);

    // A 3xx without Location is returned as is.
    assert_eq!(client.get(&format!("{base}/no-location"), ALLOWED, &[], 100).unwrap().status(), 302);

    // `Redirects::Return` hands back the 3xx; a 303 after POST continues as GET without body.
    let request = Request {
        method: "POST",
        url: &format!("{base}/post"),
        headers: &[],
        body: Some(b"payload"),
        redirects: Redirects::Return,
    };
    assert_eq!(client.request(&request, ALLOWED, 100).unwrap().status(), 303);
    let request = Request { redirects: Redirects::Follow, ..request };
    let answer = client.request(&request, ALLOWED, 100).unwrap();
    assert_eq!(answer.body, b"hello");
    let seen = server.seen.lock().unwrap();
    let post = seen.iter().rev().find(|s| s.path == "/post").unwrap();
    assert_eq!((post.method.as_str(), post.body.as_slice()), ("POST", &b"payload"[..]));
    assert_eq!(seen.last().unwrap().method, "GET");
}

#[test]
fn hosts_tls_and_timeouts() {
    let Some((_dir, server, ca)) = setup() else { return };
    let base = format!("https://localhost:{}", server.port);
    let client = client(&ca, Duration::from_millis(800));
    assert_eq!(client.get(&format!("{base}/ok"), &["example.com"], &[], 100), Err(NetError::HostNotAllowed));
    assert_eq!(
        client.get(&format!("http://localhost:{}/ok", server.port), ALLOWED, &[], 100),
        Err(NetError::HostNotAllowed)
    );
    let started = Instant::now();
    let stalled = client.get(&format!("{base}/stall"), ALLOWED, &[], 100);
    assert!(matches!(stalled, Err(NetError::Unreachable(_))), "{stalled:?}");
    assert!(started.elapsed() < Duration::from_millis(2500), "{:?}", started.elapsed());
    // Another trust store: the server's certificate does not verify.
    let system = HttpsClient::new(ClientOptions { timeout: Duration::from_secs(5), ..ClientOptions::default() });
    if let Ok(system) = system {
        assert!(matches!(system.get(&format!("{base}/ok"), ALLOWED, &[], 100), Err(NetError::Unreachable(_))));
    }
}
