//! The manager's few TLS conversations: HTTPS GETs of geodata (redirects followed, HTTPS end to
//! end), the WARP registration POST, the exit probe's fetch of Cloudflare's trace page through a
//! loopback port, and a bare TLS hello against a chain hop's Reality cover. The trust store is the
//! system CA bundle, as `ssl.create_default_context()` used it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::util::py_oserror;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn verified_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
            let config = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// `CERT_NONE` without `check_hostname`: the handshake itself is still verified.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn unverified_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = provider();
            let config = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// `str(exc)` of a failed `socket.create_connection`.
pub fn connect_error(err: &io::Error) -> String {
    if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        return "timed out".into();
    }
    let text = err.to_string();
    if let Some(reason) = text.strip_prefix("failed to lookup address information: ") {
        return match reason {
            "Name or service not known" => format!("[Errno -2] {reason}"),
            "Temporary failure in name resolution" => format!("[Errno -3] {reason}"),
            _ => reason.to_string(),
        };
    }
    py_oserror(err)
}

/// `socket.create_connection((host, port), timeout)`: every address in turn, the last error.
pub fn connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "getaddrinfo returns an empty list");
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(err) => last = err,
        }
    }
    Err(last)
}

/// A finished TLS handshake over `tcp`, with or without certificate verification.
pub fn handshake(tcp: TcpStream, server_name: &str, verify: bool) -> Result<TlsStream, String> {
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| format!("invalid server name: {err}"))?;
    let config = if verify { verified_config() } else { unverified_config() };
    let connection = ClientConnection::new(config, name).map_err(|err| err.to_string())?;
    let mut stream = StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(err) if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                return Err("_ssl.c:1011: The handshake operation timed out".into())
            }
            Err(err) => return Err(tls_error(&err)),
        }
    }
    Ok(stream)
}

fn tls_error(err: &io::Error) -> String {
    match err.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidCertificate(reason)) => {
            format!("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {reason:?}")
        }
        Some(other) => format!("[SSL] {other}"),
        None => py_oserror(err),
    }
}

/// A TLS stream read like Python's sockets with `suppress_ragged_eofs`: a peer that closes
/// without `close_notify` ends the body.
struct Lenient<R>(R);

impl<R: Read> Read for Lenient<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// At most the `max_body` bytes asked for.
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// Reads one response: the head, then up to `max_body` bytes of its body (`Content-Length`,
/// chunked, or to the end of the connection).
pub fn read_response<R: Read>(stream: R, max_body: usize) -> io::Result<Response> {
    let mut reader = BufReader::new(Lenient(stream));
    let mut head = Vec::new();
    loop {
        let before = head.len();
        reader.read_until(b'\n', &mut head)?;
        if head.len() == before {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Remote end closed connection without response"));
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "got more than 65536 bytes when reading header line",
            ));
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut parsed = httparse::Response::new(&mut headers);
    match parsed.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "BadStatusLine")),
    }
    let status = parsed.code.unwrap_or(0);
    let reason = parsed.reason.unwrap_or("").to_string();
    let headers: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).trim().to_string()))
        .collect();
    let mut response = Response { status, reason, headers, body: Vec::new() };
    let chunked = response.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = response.header("content-length").and_then(|v| v.trim().parse::<usize>().ok());
    response.body = if chunked {
        read_chunked(&mut reader, max_body)?
    } else {
        let limit = length.map_or(max_body, |length| length.min(max_body));
        let mut body = Vec::new();
        (&mut reader).take(limit as u64).read_to_end(&mut body)?;
        body
    };
    Ok(response)
}

fn read_chunked<R: BufRead>(reader: &mut R, max_body: usize) -> io::Result<Vec<u8>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "IncompleteRead");
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(invalid());
        }
        let size = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| invalid())?;
        if size == 0 || body.len() >= max_body {
            return Ok(body);
        }
        let want = size.min(max_body - body.len());
        let mut chunk = Vec::with_capacity(want);
        reader.take(want as u64).read_to_end(&mut chunk)?;
        if chunk.len() < want {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
        if want < size {
            return Ok(body);
        }
        let mut crlf = String::new();
        reader.read_line(&mut crlf)?;
    }
}

/// An absolute `http(s)://` URL split into what a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// `host` or `host:port` as written.
    pub authority: String,
    /// Path and query, at least `/`.
    pub target: String,
}

pub fn parse_url(url: &str) -> Option<Url> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let netloc = &rest[..end];
    let mut target = rest[end..].split('#').next().unwrap_or("").to_string();
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let authority = netloc.rsplit_once('@').map(|(_, host)| host).unwrap_or(netloc).to_string();
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']')?;
        (host.to_string(), after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.clone(), None),
        }
    };
    let port = match port {
        Some("") | None => default_port,
        Some(port) => port.parse().ok()?,
    };
    if host.is_empty() {
        return None;
    }
    Some(Url { scheme, host, port, authority, target })
}

/// `urljoin(base, location)` for the shapes servers send in `Location`.
pub fn join(base: &Url, location: &str) -> String {
    if location.contains("://") {
        return location.to_string();
    }
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{}://{rest}", base.scheme);
    }
    let origin = format!("{}://{}", base.scheme, base.authority);
    if location.starts_with('/') {
        return format!("{origin}{location}");
    }
    let path = base.target.split(['?']).next().unwrap_or("/");
    let directory = &path[..path.rfind('/').map_or(0, |i| i + 1)];
    format!("{origin}{directory}{location}")
}

/// Why a request did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Before a response: the connection or the handshake (`URLError`, its reason).
    Open(String),
    /// While reading the response (`OSError`, its text).
    Read(String),
}

/// One HTTPS request: connect, handshake with verification, send, read.
pub fn request(
    url: &Url,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    max_body: usize,
) -> Result<Response, Failure> {
    let tcp = connect(&url.host, url.port, timeout).map_err(|err| Failure::Open(connect_error(&err)))?;
    let mut stream = handshake(tcp, &url.host, true).map_err(Failure::Open)?;
    let mut head =
        format!("{method} {} HTTP/1.1\r\nAccept-Encoding: identity\r\nHost: {}\r\n", url.target, url.authority);
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let sent = stream.write_all(head.as_bytes()).and_then(|()| match body {
        Some(body) => stream.write_all(body),
        None => Ok(()),
    });
    sent.and_then(|()| stream.flush()).map_err(|err| Failure::Open(py_oserror(&err)))?;
    read_response(stream, max_body).map_err(|err| Failure::Read(read_error(&err)))
}

pub fn read_error(err: &io::Error) -> String {
    if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        return "The read operation timed out".into();
    }
    if err.raw_os_error().is_some() {
        return py_oserror(err);
    }
    err.to_string()
}

pub const TRACE_PATH: &str = "/cdn-cgi/trace";

/// `{ip, colo}` from Cloudflare's trace page fetched through `127.0.0.1:<port>`; the error text
/// (an `OSError` in the Python manager) when nothing answers or the answer is not the page.
pub fn probe_trace(port: u16, host: &str, timeout: f64) -> Result<serde_json::Value, String> {
    let timeout = Duration::from_secs_f64(timeout);
    let tcp = connect("127.0.0.1", port, timeout).map_err(|err| connect_error(&err))?;
    let mut tls = handshake(tcp, host, true)?;
    let head = format!(
        "GET {TRACE_PATH} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nUser-Agent: proxy-control-exit-probe/0.8\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(head.as_bytes()).and_then(|()| tls.flush()).map_err(|err| py_oserror(&err))?;
    let response = read_response(tls, 4096).map_err(|err| read_error(&err))?;
    if response.status != 200 {
        return Err(format!("trace page answered {}", response.status));
    }
    let body = String::from_utf8_lossy(&response.body).into_owned();
    let mut fields = std::collections::HashMap::new();
    for line in crate::util::py_splitlines(&body) {
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.to_string(), value.to_string());
        }
    }
    let Some(ip) = fields.get("ip") else { return Err("trace page had no ip field".into()) };
    Ok(serde_json::json!({"ip": ip, "colo": fields.get("colo").cloned().unwrap_or_default()}))
}

/// A TLS hello with the hop's SNI against its relay port: Reality answers with its cover's real
/// certificate, so a completed handshake proves the port and the cover — never fails.
pub fn check_hop_reachable(address: &str, port: u16, server_name: &str, timeout: f64) -> bool {
    let timeout = Duration::from_secs_f64(timeout);
    match connect(address, port, timeout) {
        Ok(tcp) => handshake(tcp, server_name, false).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn urls_split_and_join_like_urllib() {
        let url = parse_url("https://github.com/a/b/releases/latest/download/geosite.dat#x").unwrap();
        assert_eq!(
            (url.host.as_str(), url.port, url.target.as_str()),
            ("github.com", 443, "/a/b/releases/latest/download/geosite.dat")
        );
        assert_eq!(join(&url, "https://objects.example/x?sig=1"), "https://objects.example/x?sig=1");
        assert_eq!(join(&url, "/c/d"), "https://github.com/c/d");
        assert_eq!(join(&url, "//cdn.example/e"), "https://cdn.example/e");
        assert_eq!(join(&url, "f.dat"), "https://github.com/a/b/releases/latest/download/f.dat");
        let v6 = parse_url("http://[::1]:8080").unwrap();
        assert_eq!((v6.host.as_str(), v6.port, v6.target.as_str()), ("::1", 8080, "/"));
        assert!(parse_url("ftp://x/y").is_none());
    }

    #[test]
    fn responses_are_read_by_length_chunks_or_to_the_end() {
        let plain =
            read_response(Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello world".to_vec()), 100)
                .unwrap();
        assert_eq!((plain.status, plain.body.as_slice()), (200, &b"hello"[..]));
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec();
        assert_eq!(read_response(Cursor::new(chunked.clone()), 100).unwrap().body, b"abcde");
        assert_eq!(read_response(Cursor::new(chunked), 4).unwrap().body, b"abcd");
        let to_end = read_response(Cursor::new(b"HTTP/1.0 302 Found\r\nLocation: /x\r\n\r\nbody".to_vec()), 2).unwrap();
        assert_eq!((to_end.status, to_end.reason.as_str(), to_end.body.as_slice()), (302, "Found", &b"bo"[..]));
        assert_eq!(to_end.header("location"), Some("/x"));
        assert!(read_response(Cursor::new(Vec::new()), 10).is_err());
    }

    #[test]
    fn nothing_listening_is_unreachable() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(!check_hop_reachable("127.0.0.1", port, "panel.example.org", 1.0));
        let err = probe_trace(port, "www.cloudflare.com", 1.0).unwrap_err();
        assert!(err.contains("Connection refused"), "{err}");
    }
}
