//! The WARP account the AmneziaWG egress tunnel uses (v3.0.0).
//!
//! The host's own WARP client (`warp-svc`, proxy mode) runs MASQUE with ECDSA keys and offers SOCKS5
//! without UDP, so AmneziaWG — whose clients send UDP as much as TCP (DNS, QUIC, calls) — gets a WARP
//! device of its own: a WireGuard key pair made here, registered once at Cloudflare's client API (the
//! same call the 1.1.1.1 app makes), kept in the manager's state (0600) and reused until it is
//! deregistered. Registration answers with the tunnel address and the peer; nothing else is stored.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{json, Map, Value};

use crate::ipnet::{format_v4, parse_v4};
use crate::keys::{b64, generate_private, public_key, unb64};
use crate::util::{iso_millis_z, parse_int};

pub const API: &str = "https://api.cloudflareclient.com/v0a5641";
pub const HEADERS: [(&str, &str); 3] = [
    ("User-Agent", "okhttp/3.12.1"),
    ("CF-Client-Version", "a-6.38.9-5641"),
    ("Content-Type", "application/json; charset=UTF-8"),
];
pub const PORT: u16 = 2408;
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_BODY: usize = 65536;
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Registration failed or answered something this manager cannot use. Never carries a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpError(pub String);

impl std::fmt::Display for WarpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// (method, url, headers, body or None) -> (status, parsed JSON or None). Injected in tests.
pub type Opener = Box<
    dyn Fn(&str, &str, &[(String, String)], Option<&[u8]>) -> Result<(u16, Option<Value>), WarpError> + Send + Sync,
>;

fn headers(extra: &[(&str, String)]) -> Vec<(String, String)> {
    HEADERS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .chain(extra.iter().map(|(k, v)| (k.to_string(), v.clone())))
        .collect()
}

/// `str(value)` of a JSON value, as the Python manager stored the id and the token.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => other.to_string(),
    }
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `str(IPv4Address(value))`: a dotted quad, or an integer below 2^32.
fn ipv4(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => parse_v4(text).map(format_v4),
        Value::Number(number) => number.as_u64().and_then(|n| u32::try_from(n).ok()).map(format_v4),
        _ => None,
    }
}

/// A new WARP device: the stored account (with its private key) or `WarpError`.
pub fn register(opener: &Opener) -> Result<Value, WarpError> {
    let private = generate_private();
    let now = iso_millis_z(SystemTime::now());
    let body = json!({"key": b64(&public_key(&private)), "install_id": "", "fcm_token": "", "tos": now,
                      "model": "PC", "serial_number": "", "locale": "en_US"});
    let (status, data) =
        opener("POST", &format!("{API}/reg"), &headers(&[]), Some(crate::pyjson::plain(&body).as_bytes()))?;
    let data = match data {
        Some(Value::Object(data)) if status == 200 => data,
        _ => return Err(WarpError(format!("WARP registration refused (HTTP {status})"))),
    };
    let shape = || WarpError("WARP registration answered an unexpected shape".into());
    let config = data.get("config").ok_or_else(shape)?;
    let peer = config.get("peers").and_then(|peers| peers.get(0)).ok_or_else(shape)?;
    let address = ipv4(config.pointer("/interface/addresses/v4").ok_or_else(shape)?).ok_or_else(shape)?;
    let endpoint_raw = peer.pointer("/endpoint/v4").and_then(Value::as_str).ok_or_else(shape)?;
    let endpoint_host = endpoint_raw.rsplit_once(':').map(|(host, _)| host).unwrap_or(endpoint_raw);
    let endpoint = parse_v4(endpoint_host).map(format_v4).ok_or_else(shape)?;
    let peer_key = peer.get("public_key").and_then(Value::as_str).ok_or_else(shape)?;
    unb64(peer_key).map_err(|_| shape())?;
    let device_id = py_str(data.get("id").ok_or_else(shape)?);
    let token = py_str(data.get("token").ok_or_else(shape)?);
    if device_id.is_empty() || token.is_empty() {
        return Err(shape());
    }
    let account_type = data
        .get("account")
        .filter(|account| truthy(account))
        .and_then(|account| account.get("account_type"))
        .filter(|kind| truthy(kind))
        .map(py_str)
        .unwrap_or_default();
    Ok(json!({
        "id": device_id, "token": token, "private_key": b64(&private), "address": address,
        "peer_public_key": peer_key, "endpoint": format!("{endpoint}:{PORT}"),
        "account_type": account_type,
        "registered_at": iso_millis_z(SystemTime::now()),
    }))
}

/// Remove the device at Cloudflare. A device already gone (404) counts as removed. The manager keeps
/// its registration; this is the module's API for operators and tests, as in the Python manager.
#[allow(dead_code)]
pub fn deregister(account: &Map<String, Value>, opener: &Opener) -> Result<(), WarpError> {
    let field = |key: &str| account.get(key).map(py_str).unwrap_or_default();
    let headers = headers(&[("Authorization", format!("Bearer {}", field("token")))]);
    let (status, _) = opener("DELETE", &format!("{API}/reg/{}", field("id")), &headers, None)?;
    if !matches!(status, 200 | 204 | 404) {
        return Err(WarpError(format!("WARP deregistration refused (HTTP {status})")));
    }
    Ok(())
}

/// A stored account this manager can bring a tunnel up with.
pub fn valid_account(account: &Value) -> bool {
    let Some(account) = account.as_object() else { return false };
    let text = |key: &str| account.get(key).and_then(Value::as_str);
    let keys_ok =
        [text("private_key"), text("peer_public_key")].iter().all(|key| key.is_some_and(|k| unb64(k).is_ok()));
    let address_ok = account.get("address").and_then(ipv4).is_some();
    let endpoint_ok = text("endpoint").is_some_and(|endpoint| {
        let (host, port) = endpoint.rsplit_once(':').unwrap_or(("", endpoint));
        parse_v4(host).is_some() && parse_int(port, 10).is_some_and(|port| 0 < port && port < 65536)
    });
    let present = |key: &str| account.get(key).is_some_and(truthy);
    keys_ok && address_ok && endpoint_ok && present("id") && present("token")
}

// ------------------------------------------------------------------ HTTPS, as urllib did it

fn unreachable(kind: &str) -> WarpError {
    WarpError(format!("WARP API unreachable: {kind}"))
}

fn tls_config() -> io::Result<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let bundle = std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| CA_BUNDLE.into());
    let mut roots = rustls::RootCertStore::empty();
    let certificates = CertificateDer::pem_file_iter(&bundle).map_err(io::Error::other)?;
    roots.add_parsable_certificates(certificates.filter_map(Result::ok));
    if roots.is_empty() {
        return Err(io::Error::other("no trusted certificates"));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn connect(host: &str) -> io::Result<TcpStream> {
    let mut last = io::Error::other("address resolves to nothing");
    for address in (host, 443).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last = err,
        }
    }
    Err(last)
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 || out.len() >= MAX_BODY {
            return Some(out);
        }
        // A chunk cut short by the read cap still counts up to where it was cut.
        let take = size.min(data.len());
        out.extend_from_slice(&data[..take]);
        if take < size || data.len() < size + 2 {
            return Some(out);
        }
        data = &data[size + 2..];
    }
}

/// One HTTPS request to the WARP API: `urllib.request.urlopen` with a 20 s timeout and the system
/// trust store. A status of 300 or more answers `(status, None)`, as `HTTPError` did; the body of
/// a success is read up to 64 KiB and parsed as JSON.
pub fn https(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Option<Value>), WarpError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| unreachable("URLError"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let tcp = connect(host).map_err(|_| unreachable("URLError"))?;
    let _ = tcp.set_read_timeout(Some(TIMEOUT));
    let _ = tcp.set_write_timeout(Some(TIMEOUT));
    let config = tls_config().map_err(|_| unreachable("URLError"))?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| unreachable("URLError"))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name).map_err(|_| unreachable("URLError"))?;
    let mut tls = rustls::StreamOwned::new(connection, tcp);
    let mut head = format!("{method} {path} HTTP/1.1\r\nAccept-Encoding: identity\r\nHost: {host}\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let sent =
        tls.write_all(head.as_bytes()).and_then(|()| tls.write_all(body.unwrap_or(&[]))).and_then(|()| tls.flush());
    sent.map_err(|_| unreachable("URLError"))?;

    // Everything up to the response head is urlopen's own work: its failures are a URLError.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_len = loop {
        if let Some(end) = find_head_end(&raw) {
            break end;
        }
        match tls.read(&mut chunk) {
            Ok(0) => return Err(unreachable("URLError")),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(unreachable("URLError")),
        }
        if raw.len() > 64 * 1024 {
            return Err(unreachable("URLError"));
        }
    };
    let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut parsed_headers);
    if !matches!(response.parse(&raw[..head_len]), Ok(httparse::Status::Complete(_))) {
        return Err(unreachable("URLError"));
    }
    let status = response.code.ok_or_else(|| unreachable("URLError"))?;
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).to_ascii_lowercase())
    };
    let chunked = header("transfer-encoding").is_some_and(|value| value.contains("chunked"));
    let length = header("content-length").and_then(|value| value.trim().parse::<usize>().ok());
    if status >= 300 {
        return Ok((status, None));
    }

    let mut body = raw[head_len..].to_vec();
    let cap = MAX_BODY + 16 * 1024;
    let complete = |body: &[u8]| match length {
        Some(length) if !chunked => body.len() >= length,
        _ => chunked && body.windows(5).any(|w| w == b"0\r\n\r\n"),
    };
    while body.len() < cap && !complete(&body) {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            // A peer that closes without close_notify still ended the body.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Err(unreachable("TimeoutError"))
            }
            Err(_) => return Err(unreachable("OSError")),
        }
    }
    let mut body = if chunked { dechunk(&body).unwrap_or_default() } else { body };
    if let Some(length) = length.filter(|_| !chunked) {
        body.truncate(length);
    }
    body.truncate(MAX_BODY);
    if body.is_empty() {
        return Ok((status, None));
    }
    serde_json::from_slice(&body).map(|value| (status, Some(value))).map_err(|_| unreachable("JSONDecodeError"))
}

/// The production opener.
pub fn https_opener() -> Opener {
    Box::new(https)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    pub fn peer_key() -> String {
        let private: [u8; 32] = core::array::from_fn(|i| i as u8 + 2);
        b64(&public_key(&private))
    }

    pub fn registrar(status: u16, calls: Arc<Mutex<Vec<(String, String)>>>) -> Opener {
        Box::new(move |method, url, headers, body| {
            calls.lock().unwrap().push((method.to_string(), url.to_string()));
            if method == "DELETE" {
                return Ok((204, None));
            }
            if status != 200 {
                return Ok((status, None));
            }
            let sent: Value = serde_json::from_slice(body.unwrap()).unwrap();
            assert!(unb64(sent["key"].as_str().unwrap()).is_ok());
            assert!(headers.iter().any(|(name, value)| name == "CF-Client-Version" && !value.is_empty()));
            Ok((
                200,
                Some(json!({"id": "dev-1", "token": "tok-1", "account": {"account_type": "free"}, "config": {
                    "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700::1"}},
                    "peers": [{"public_key": peer_key(),
                               "endpoint": {"v4": "162.159.192.9:0", "host": "engage.cloudflareclient.com:2408"}}]}})),
            ))
        })
    }

    #[test]
    fn registration_parses_only_what_it_needs_and_refuses_odd_answers() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let account = register(&registrar(200, calls.clone())).unwrap();
        assert!(valid_account(&account) && account["endpoint"] == "162.159.192.9:2408");
        let keys: Vec<&String> = account.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["id", "token", "private_key", "address", "peer_public_key", "endpoint", "account_type", "registered_at"]
        );
        assert_eq!((&account["address"], &account["account_type"]), (&json!("172.16.0.2"), &json!("free")));
        let shapeless: Opener = Box::new(|_, _, _, _| Ok((200, Some(json!({"id": "x", "config": {}})))));
        assert!(register(&shapeless).is_err());
        assert_eq!(register(&registrar(403, calls.clone())).unwrap_err().0, "WARP registration refused (HTTP 403)");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let opener: Opener = Box::new(move |method, url, headers, _| {
            let auth = headers.iter().find(|(name, _)| name == "Authorization").unwrap().1.clone();
            recorder.lock().unwrap().push((method.to_string(), url.to_string(), auth));
            Ok((204, None))
        });
        deregister(account.as_object().unwrap(), &opener).unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [("DELETE".to_string(), format!("{API}/reg/dev-1"), "Bearer tok-1".to_string())]
        );
    }

    #[test]
    fn stored_accounts_are_checked_before_use() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let account = register(&registrar(200, calls)).unwrap();
        for (key, bad) in [
            ("private_key", json!("short")),
            ("peer_public_key", json!(null)),
            ("address", json!("172.16.0")),
            ("endpoint", json!("162.159.192.9:0")),
            ("endpoint", json!("162.159.192.9")),
            ("id", json!("")),
            ("token", json!(null)),
        ] {
            let mut broken = account.clone();
            broken[key] = bad;
            assert!(!valid_account(&broken), "{key}");
        }
        assert!(!valid_account(&json!([])));
    }

    #[test]
    fn chunked_bodies_are_reassembled() {
        assert_eq!(dechunk(b"3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n").unwrap(), b"{\"a\":1}");
        assert!(dechunk(b"zz\r\n").is_none());
    }

    /// A live call to Cloudflare's API that changes nothing (deleting a device that does not
    /// exist): proves DNS, TCP, TLS with the system trust store, and the HTTP exchange. Run by hand:
    /// `cargo test -- --ignored warp_api_answers_over_tls`.
    #[test]
    #[ignore]
    fn warp_api_answers_over_tls() {
        let headers = headers(&[("Authorization", "Bearer not-a-token".into())]);
        let (status, _) = https("DELETE", &format!("{API}/reg/not-a-device"), &headers, None).unwrap();
        assert!((400..500).contains(&status), "{status}");
    }
}
