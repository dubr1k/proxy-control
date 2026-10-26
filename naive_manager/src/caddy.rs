//! What the manager does to Caddy: adapt and validate a Caddyfile through the admin API,
//! load the adapted config with the private listener moved to 4443, and probe the cover site
//! over TLS on that listener. The admin requests are byte-identical to what the Python
//! manager's `urllib` sent.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Map, Value};

use crate::error::{Error, Result};

pub const ADMIN_ADDRESS: &str = "127.0.0.1:2019";
const ADMIN_TIMEOUT: Duration = Duration::from_secs(20);

/// The Caddy admin endpoint (loopback, plain HTTP).
#[derive(Debug, Clone)]
pub struct Admin {
    pub address: String,
}

impl Default for Admin {
    fn default() -> Self {
        Self { address: ADMIN_ADDRESS.into() }
    }
}

/// The request `urllib.request.urlopen` wrote for a POST with these headers.
pub fn request_bytes(host: &str, path: &str, content_type: &str, cache_control: bool, body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nHost: {host}\r\n\
         User-Agent: Python-urllib/3.13\r\nContent-Type: {content_type}\r\n",
        body.len()
    );
    if cache_control {
        head.push_str("Cache-Control: must-revalidate\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>> {
    let invalid = || Error::Os("malformed chunked response".into());
    let mut out = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n").ok_or_else(invalid)?;
        let size_text = std::str::from_utf8(&data[..line_end]).map_err(|_| invalid())?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).map_err(|_| invalid())?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err(invalid());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

impl Admin {
    fn post(&self, path: &str, content_type: &str, cache_control: bool, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let address: SocketAddr = self
            .address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::Os("admin address resolves to nothing".into()))?;
        let mut stream = TcpStream::connect_timeout(&address, ADMIN_TIMEOUT)?;
        stream.set_read_timeout(Some(ADMIN_TIMEOUT))?;
        stream.set_write_timeout(Some(ADMIN_TIMEOUT))?;
        stream.write_all(&request_bytes(&self.address, path, content_type, cache_control, body))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;
        let head_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| Error::Os("Remote end closed connection without response".into()))?;
        let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| Error::Os("bad status line".into()))?;
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        let body = &raw[head_end + 4..];
        let header = |name: &str| headers.iter().find(|(key, _)| key == name).map(|(_, v)| v.as_str());
        let body = if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            dechunk(body)?
        } else if let Some(length) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            body[..length.min(body.len())].to_vec()
        } else {
            body.to_vec()
        };
        // `urlopen` raises HTTPError for anything outside 2xx.
        if !(200..300).contains(&status) {
            return Err(Error::Os(format!("HTTP Error {status}")));
        }
        Ok((status, body))
    }

    /// `caddy_adapt`: POST the file to `/adapt?adapter=caddyfile&validate=true`; the adapted
    /// config, unwrapped from Caddy 2.11's `{"result": …, "warnings": …}` envelope.
    pub fn adapt(&self, path: &Path) -> Result<Value> {
        let body = std::fs::read(path)?;
        let (status, payload) = self.post("/adapt?adapter=caddyfile&validate=true", "text/caddyfile", false, &body)?;
        if status != 200 {
            return Err(Error::runtime("Caddy validation failed"));
        }
        let payload: Value =
            serde_json::from_slice(&payload).map_err(|_| Error::value("Caddy returned invalid JSON"))?;
        let Value::Object(mut payload) = payload else {
            return Err(Error::runtime("Caddy returned an invalid configuration"));
        };
        let config = match payload.remove("result") {
            Some(result) => result,
            None => Value::Object(payload),
        };
        if !config.is_object() {
            return Err(Error::runtime("Caddy returned an invalid configuration"));
        }
        Ok(config)
    }

    /// `command_reload`: adapt the live Caddyfile, move the listener, POST it to `/load`.
    pub fn reload(&self, caddyfile: &Path) -> Result<()> {
        let config = rewrite_listener(self.adapt(caddyfile)?)?;
        let body = crate::pyjson::dumps(&config, crate::pyjson::COMPACT);
        let (status, _) = self.post("/load", "application/json", true, body.as_bytes())?;
        if status != 200 && status != 204 {
            return Err(Error::runtime("Caddy reload failed"));
        }
        Ok(())
    }
}

/// `value.get(key, {})`: a missing level reads as an empty dict, a non-dict is an error.
fn step<'a>(value: Option<&'a mut Value>, key: &str) -> Result<Option<&'a mut Value>> {
    match value {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(map.get_mut(key)),
        Some(_) => Err(Error::Other("'get' on a non-object".into())),
    }
}

/// The private generation listens on 4443 instead of 443, without HTTP->HTTPS redirects.
pub fn rewrite_listener(mut config: Value) -> Result<Value> {
    match step(step(step(Some(&mut config), "apps")?, "http")?, "servers")? {
        Some(servers) => finish(servers)?,
        None => finish(&mut Value::Object(Map::new()))?,
    }
    Ok(config)
}

fn finish(servers: &mut Value) -> Result<()> {
    let Value::Object(servers) = servers else {
        return Err(Error::runtime("Caddy returned an invalid HTTP configuration"));
    };
    let mut rewritten = false;
    for server in servers.values_mut() {
        let Some(server) = server.as_object_mut() else { continue };
        let Some(Value::Array(listen)) = server.get_mut("listen") else { continue };
        for address in listen.iter_mut() {
            match address.as_str() {
                Some("127.0.0.1:443") => *address = Value::from("127.0.0.1:4443"),
                Some(":443") => *address = Value::from(":4443"),
                _ => {}
            }
        }
        let is_naive = listen.iter().any(|a| matches!(a.as_str(), Some(":4443" | "127.0.0.1:4443")));
        if is_naive {
            let automatic = server.entry("automatic_https").or_insert_with(|| Value::Object(Map::new()));
            let Value::Object(automatic) = automatic else {
                return Err(Error::runtime("Caddy returned invalid automatic HTTPS settings"));
            };
            automatic.insert("disable_redirects".into(), Value::Bool(true));
            rewritten = true;
        }
    }
    if !rewritten {
        return Err(Error::runtime("Caddy configuration has no Naive listener"));
    }
    Ok(())
}

/// Accepts any server certificate but still checks the handshake signatures with the
/// certificate's key: the probe talks to a loopback process, and a private or self-signed
/// chain must not make the manager permanently unhealthy while the tunnel works.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Built once and without a CA store: the probe verifies no chain, and loading a store on
/// every health check was most of the Python manager's idle CPU.
pub fn probe_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .expect("the ring provider supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Proves the private listener still serves the cover site for this SNI.
pub fn https_probe(host: &str, port: u16) -> Result<()> {
    let timeout = Duration::from_secs(5);
    let tls_error = |err: rustls::Error| Error::Os(format!("TLS: {err}"));
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let name =
        rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|err| Error::value(err.to_string()))?;
    let connection = rustls::ClientConnection::new(probe_config(), name).map_err(tls_error)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())?;
    let mut buffer = [0u8; 128];
    let read = tls.read(&mut buffer)?;
    // `tls.recv(128).split(b"\r\n", 1)[0]`
    let end = buffer[..read].windows(2).position(|w| w == b"\r\n").unwrap_or(read);
    let status = &buffer[..end];
    if !(status.starts_with(b"HTTP/1.1 200") || status.starts_with(b"HTTP/2 200")) {
        return Err(Error::runtime("NaiveProxy cover probe failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::TcpListener;

    #[test]
    fn private_listener_rewrite_disables_automatic_https_redirects() {
        let config = json!({"apps": {"http": {"servers": {
            "naive": {"listen": [":443", "127.0.0.1:443"]},
            "unrelated": {"listen": ["127.0.0.1:8443"]},
        }}}});
        let rewritten = rewrite_listener(config).unwrap();
        let naive = &rewritten["apps"]["http"]["servers"]["naive"];
        assert_eq!(naive["listen"], json!([":4443", "127.0.0.1:4443"]));
        assert_eq!(naive["automatic_https"], json!({"disable_redirects": true}));
        assert!(rewritten["apps"]["http"]["servers"]["unrelated"].get("automatic_https").is_none());
        assert!(rewrite_listener(json!({"apps": {"http": {"servers": {}}}})).is_err());
        assert!(rewrite_listener(json!({})).is_err());
    }

    /// One HTTP exchange on an ephemeral port: what arrived, and a canned reply.
    fn serve_once(reply: Vec<u8>) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut chunk = [0u8; 65536];
            loop {
                let n = stream.read(&mut chunk).unwrap();
                data.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if body.len() >= length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            stream.write_all(&reply).unwrap();
            data
        });
        (address, thread)
    }

    fn reply(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
            .into_bytes()
    }

    #[test]
    fn caddy_adapt_unwraps_caddy_211_envelope() {
        let dir = crate::tests::tempdir("caddy-adapt");
        let candidate = dir.join("Caddyfile");
        std::fs::write(&candidate, "example.com { respond 200 }").unwrap();
        let (address, server) = serve_once(reply(r#"{"result":{"apps":{"http":{}}},"warnings":[]}"#));
        let admin = Admin { address: address.clone() };
        assert_eq!(admin.adapt(&candidate).unwrap(), json!({"apps": {"http": {}}}));
        let request = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(request.starts_with("POST /adapt?adapter=caddyfile&validate=true HTTP/1.1\r\n"));
    }

    #[test]
    fn admin_requests_are_byte_identical_to_urllib() {
        // Captured from naive_manager.server.caddy_adapt / command_reload in python:3.13.5.
        assert_eq!(
            request_bytes(ADMIN_ADDRESS, "/adapt?adapter=caddyfile&validate=true", "text/caddyfile", false, ":4443 {\n    respond é\n}\n".as_bytes()),
            b"POST /adapt?adapter=caddyfile&validate=true HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: 25\r\nHost: 127.0.0.1:2019\r\nUser-Agent: Python-urllib/3.13\r\nContent-Type: text/caddyfile\r\nConnection: close\r\n\r\n:4443 {\n    respond \xc3\xa9\n}\n"
        );
        let config = json!({"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [{"handle": [
            {"handler": "forward_proxy", "x": 1.5e-05, "y": "é\u{2028}"}]}]}}}}});
        let body = crate::pyjson::dumps(&rewrite_listener(config).unwrap(), crate::pyjson::COMPACT);
        let expected: &[u8] = b"POST /load HTTP/1.1\r\nAccept-Encoding: identity\r\nContent-Length: 187\r\nHost: 127.0.0.1:2019\r\nUser-Agent: Python-urllib/3.13\r\nContent-Type: application/json\r\nCache-Control: must-revalidate\r\nConnection: close\r\n\r\n{\"apps\":{\"http\":{\"servers\":{\"srv0\":{\"listen\":[\":4443\"],\"routes\":[{\"handle\":[{\"handler\":\"forward_proxy\",\"x\":1.5e-05,\"y\":\"\\u00e9\\u2028\"}]}],\"automatic_https\":{\"disable_redirects\":true}}}}}}";
        assert_eq!(request_bytes(ADMIN_ADDRESS, "/load", "application/json", true, body.as_bytes()), expected);
        assert_eq!(Admin::default().address, "127.0.0.1:2019");
    }

    #[test]
    fn reload_posts_the_rewritten_config_and_refuses_errors() {
        let dir = crate::tests::tempdir("caddy-reload");
        let caddyfile = dir.join("Caddyfile");
        std::fs::write(&caddyfile, ":443 {\n}\n").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for answer in [
                reply(r#"{"apps":{"http":{"servers":{"s":{"listen":[":443"]}}}}}"#),
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut data = vec![0u8; 65536];
                let n = stream.read(&mut data).unwrap();
                seen.push(String::from_utf8_lossy(&data[..n]).into_owned());
                stream.write_all(&answer).unwrap();
            }
            seen
        });
        Admin { address: address.clone() }.reload(&caddyfile).unwrap();
        let seen = server.join().unwrap();
        assert!(seen[1].starts_with("POST /load HTTP/1.1\r\n") && seen[1].contains(r#""listen":[":4443"]"#));
        let (address, _server) = serve_once(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec());
        assert!(Admin { address }.adapt(&caddyfile).is_err());
    }

    fn openssl_self_signed(dir: &Path) -> bool {
        std::process::Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout"])
            .arg(dir.join("key.pem"))
            .arg("-out")
            .arg(dir.join("cert.pem"))
            .args(["-days", "1", "-subj", "/CN=naive.example.com", "-addext", "subjectAltName=DNS:naive.example.com"])
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    fn cover_probe_accepts_a_locally_untrusted_cover_certificate() {
        use rustls::pki_types::pem::PemObject;
        let dir = crate::tests::tempdir("cover-probe");
        if !openssl_self_signed(&dir) {
            eprintln!("openssl is unavailable");
            return;
        }
        let certs = rustls::pki_types::CertificateDer::pem_file_iter(dir.join("cert.pem"))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(dir.join("key.pem")).unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), stream);
            let mut request = [0u8; 4096];
            let _ = tls.read(&mut request);
            let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        });
        https_probe("naive.example.com", port).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn https_probe_reuses_one_context_without_a_ca_store() {
        let first = probe_config();
        assert!(Arc::ptr_eq(&first, &probe_config()));
        // No chain verification: the verifier is the accept-any one, not a WebPKI store.
        assert!(format!("{:?}", first.crypto_provider()).contains("ring") || first.alpn_protocols.is_empty());
        assert!(first.alpn_protocols.is_empty());
    }
}
