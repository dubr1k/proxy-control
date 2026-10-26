//! A blocking HTTPS client for the host binaries (`version_agent/upstream.py:84-135`,
//! `version_agent/service.py:143-171`).
//!
//! - TLS through rustls with the `ring` provider; the trust store is the system bundle
//!   (`rustls-native-certs`, as `ssl.create_default_context()` used it).
//! - Every request URL must be `https` on an allowed host without user info; redirects
//!   (301/302/303/307/308, at most 10) are followed **by this module**, and every hop must stay
//!   on `https` and inside the allowed hosts — checking only the last hop would already have sent
//!   a request elsewhere.
//! - A non-2xx answer is not an error: it comes back as `(status, headers, empty body)`, as
//!   `fetch_https` returned urllib's `HTTPError`.
//! - Bodies are read up to a caller's cap (`maximum + 1` bytes read, more is "too large").
//! - Timeouts are per operation (resolve, connect, each read and write; 30 s by default), like
//!   urllib's socket timeout. Proxy environment variables are honoured as urllib did.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};
use ureq::{config::AutoHeaderValue, Agent};

use crate::pytext::py_title;
use crate::url;

/// The upstream hosts the version-agent may reach (`upstream.ALLOWED_HOSTS`).
pub const UPSTREAM_HOSTS: &[&str] = &[
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "ghcr.io",
    "registry-1.docker.io",
    "auth.docker.io",
    "index.docker.io",
];
/// The version-agent's User-Agent.
pub const AGENT_USER_AGENT: &str = "proxy-control-version-agent/1";
/// urllib's `HTTPRedirectHandler.max_redirections`.
pub const MAX_REDIRECTS: u32 = 10;
/// urllib's socket timeout used by `open_allowed`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Which certificates are trusted.
#[derive(Debug, Clone)]
pub enum Roots {
    /// The system bundle (`/etc/ssl/certs`, `SSL_CERT_FILE`).
    System,
    /// Exactly these DER certificates (tests, pinned endpoints).
    Der(Vec<Vec<u8>>),
}

/// How a client is built.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub user_agent: String,
    /// Per-operation timeout.
    pub timeout: Duration,
    pub max_redirects: u32,
    pub roots: Roots,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            user_agent: AGENT_USER_AGENT.into(),
            timeout: DEFAULT_TIMEOUT,
            max_redirects: MAX_REDIRECTS,
            roots: Roots::System,
        }
    }
}

/// `UpstreamError` texts of the version-agent; callers with their own wording (artifact
/// downloads) match on the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// `upstream host is not allowed`: the first URL is not `https`, has no or another host, or
    /// carries user info.
    HostNotAllowed,
    /// `upstream redirect left the allowed hosts`.
    RedirectLeftAllowedHosts,
    /// `upstream answer is too large`.
    TooLarge,
    /// `upstream unreachable: <detail>` (DNS, TCP, TLS, timeouts, malformed answers).
    Unreachable(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::HostNotAllowed => f.write_str("upstream host is not allowed"),
            NetError::RedirectLeftAllowedHosts => f.write_str("upstream redirect left the allowed hosts"),
            NetError::TooLarge => f.write_str("upstream answer is too large"),
            NetError::Unreachable(detail) => write!(f, "upstream unreachable: {detail}"),
        }
    }
}

impl std::error::Error for NetError {}

/// The status line and headers of the final hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    /// `{k.title(): v}`: title-cased names, the last value of a repeated header wins.
    pub headers: BTreeMap<String, String>,
    /// Every header as received (repeated ones such as `Set-Cookie` kept), names lower-case.
    pub raw_headers: Vec<(String, String)>,
    /// The URL that answered (after redirects).
    pub final_url: String,
}

impl Head {
    /// A header by case-insensitive name (the last value).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.raw_headers.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A complete answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub head: Head,
    pub body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.head.status
    }
}

/// Whether redirects are followed (each hop checked against the allowed hosts) or returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    Follow,
    Return,
}

/// A request beyond a plain GET.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<&'a [u8]>,
    pub redirects: Redirects,
}

/// The client; cheap to clone, keeps idle connections for 15 s.
#[derive(Clone)]
pub struct HttpsClient {
    agent: Agent,
    options: ClientOptions,
}

fn unreachable(err: impl std::fmt::Display) -> NetError {
    NetError::Unreachable(err.to_string())
}

/// `_check_host`: `https`, a host in `allowed`, no user name or password.
pub fn check_host(target: &str, allowed: &[&str]) -> Result<(), NetError> {
    let parts = url::split(target);
    let host_allowed = parts.hostname().is_some_and(|host| allowed.contains(&host.as_str()));
    if parts.scheme != "https" || !host_allowed || parts.username().is_some() || parts.password().is_some() {
        return Err(NetError::HostNotAllowed);
    }
    Ok(())
}

/// A redirect hop stays on `https` and inside `allowed` (`_AllowedRedirects`).
fn hop_allowed(target: &str, allowed: &[&str]) -> bool {
    let parts = url::split(target);
    parts.scheme == "https" && parts.hostname().is_some_and(|host| allowed.contains(&host.as_str()))
}

impl HttpsClient {
    pub fn new(options: ClientOptions) -> Result<HttpsClient, NetError> {
        let certificates: Vec<Certificate<'static>> = match &options.roots {
            Roots::System => {
                let loaded = rustls_native_certs::load_native_certs();
                if loaded.certs.is_empty() {
                    return Err(NetError::Unreachable("no system root certificates".into()));
                }
                loaded.certs.iter().map(|der| Certificate::from_der(der.as_ref()).to_owned()).collect()
            }
            Roots::Der(ders) => ders.iter().map(|der| Certificate::from_der(der).to_owned()).collect(),
        };
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::Specific(Arc::new(certificates)))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let timeout = Some(options.timeout);
        let agent: Agent = Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(AutoHeaderValue::None)
            .accept(AutoHeaderValue::None)
            .accept_encoding(AutoHeaderValue::Provided(Arc::new("identity".into())))
            .timeout_resolve(timeout)
            .timeout_connect(timeout)
            .timeout_send_request(timeout)
            .timeout_recv_response(timeout)
            .timeout_per_read(timeout)
            .timeout_per_write(timeout)
            .build()
            .into();
        Ok(HttpsClient { agent, options })
    }

    /// The version-agent's client: system roots, its User-Agent, 30 s.
    pub fn upstream() -> Result<HttpsClient, NetError> {
        HttpsClient::new(ClientOptions::default())
    }

    /// `fetch_https(url, headers, maximum)`: GET on `allowed` hosts, redirects followed and
    /// checked; a 2xx body up to `maximum` bytes, otherwise an empty body.
    pub fn get(
        &self,
        target: &str,
        allowed: &[&str],
        headers: &[(&str, &str)],
        maximum: u64,
    ) -> Result<Response, NetError> {
        let request = Request { method: "GET", url: target, headers, body: None, redirects: Redirects::Follow };
        self.request(&request, allowed, maximum)
    }

    /// Any method; 2xx bodies are read up to `maximum` bytes.
    pub fn request(&self, request: &Request<'_>, allowed: &[&str], maximum: u64) -> Result<Response, NetError> {
        let mut body = Vec::new();
        let head = self.exchange(request, allowed, maximum, &mut body)?;
        Ok(Response { head, body })
    }

    /// A GET whose 2xx body streams into `sink` (at most `maximum` bytes; more is
    /// [`NetError::TooLarge`] after `maximum` bytes were written).
    pub fn download(
        &self,
        target: &str,
        allowed: &[&str],
        headers: &[(&str, &str)],
        maximum: u64,
        sink: &mut dyn Write,
    ) -> Result<Head, NetError> {
        let request = Request { method: "GET", url: target, headers, body: None, redirects: Redirects::Follow };
        self.exchange(&request, allowed, maximum, sink)
    }

    fn exchange(
        &self,
        request: &Request<'_>,
        allowed: &[&str],
        maximum: u64,
        sink: &mut dyn Write,
    ) -> Result<Head, NetError> {
        check_host(request.url, allowed)?;
        let mut current = request.url.to_string();
        let mut method = request.method.to_string();
        let mut body = request.body;
        let mut hops = 0;
        loop {
            let response = self.send(&method, &current, request.headers, body)?;
            let status = response.status().as_u16();
            let head = head_of(&response, &current);
            let location = head.header("location").or_else(|| head.header("uri")).map(str::to_string);
            if request.redirects == Redirects::Follow && matches!(status, 301 | 302 | 303 | 307 | 308) {
                if let Some(location) = location {
                    if hops >= self.options.max_redirects {
                        // urllib: an `HTTPError` with the redirect's status.
                        return Ok(head);
                    }
                    let next = url::join(&current, &location);
                    if !hop_allowed(&next, allowed) {
                        return Err(NetError::RedirectLeftAllowedHosts);
                    }
                    if status == 303 || ((status == 301 || status == 302) && method == "POST") {
                        method = "GET".into();
                        body = None;
                    }
                    current = next;
                    hops += 1;
                    continue;
                }
            }
            if !hop_allowed(&current, allowed) {
                return Err(NetError::RedirectLeftAllowedHosts);
            }
            if !(200..300).contains(&status) {
                return Ok(head);
            }
            let mut reader = response.into_body().into_reader();
            copy_bounded(&mut reader, sink, maximum)?;
            return Ok(head);
        }
    }

    fn send(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<ureq::http::Response<ureq::Body>, NetError> {
        let user_agent = self.options.user_agent.as_str();
        let caller_agent = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent"));
        let mut all: Vec<(&str, &str)> = Vec::new();
        if !caller_agent {
            all.push(("User-Agent", user_agent));
        }
        all.extend_from_slice(headers);
        macro_rules! with_headers {
            ($builder:expr) => {{
                let mut builder = $builder;
                for (name, value) in &all {
                    builder = builder.header(*name, *value);
                }
                builder
            }};
        }
        let result = match method {
            "GET" => with_headers!(self.agent.get(target)).call(),
            "HEAD" => with_headers!(self.agent.head(target)).call(),
            "DELETE" => with_headers!(self.agent.delete(target)).call(),
            "POST" => with_headers!(self.agent.post(target)).send(body.unwrap_or_default()),
            "PUT" => with_headers!(self.agent.put(target)).send(body.unwrap_or_default()),
            "PATCH" => with_headers!(self.agent.patch(target)).send(body.unwrap_or_default()),
            other => return Err(NetError::Unreachable(format!("unsupported method {other}"))),
        };
        result.map_err(unreachable)
    }
}

fn head_of(response: &ureq::http::Response<ureq::Body>, current: &str) -> Head {
    let mut headers = BTreeMap::new();
    let mut raw_headers = Vec::new();
    for (name, value) in response.headers() {
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        headers.insert(py_title(name.as_str()), value.clone());
        raw_headers.push((name.as_str().to_string(), value));
    }
    Head { status: response.status().as_u16(), headers, raw_headers, final_url: current.to_string() }
}

fn copy_bounded(reader: &mut dyn Read, sink: &mut dyn Write, maximum: u64) -> Result<u64, NetError> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let want = (buffer.len() as u64).min(maximum - total + 1) as usize;
        let read = match reader.read(&mut buffer[..want]) {
            Ok(0) => return Ok(total),
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(unreachable(err)),
        };
        total += read as u64;
        if total > maximum {
            return Err(NetError::TooLarge);
        }
        sink.write_all(&buffer[..read]).map_err(unreachable)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_checks_match_upstream_py() {
        assert!(check_host("https://api.github.com/repos/x", UPSTREAM_HOSTS).is_ok());
        assert!(check_host("https://API.GitHub.com/repos/x", UPSTREAM_HOSTS).is_ok());
        assert!(check_host("https://api.github.com:443/x", UPSTREAM_HOSTS).is_ok());
        for bad in [
            "http://api.github.com/x",
            "https://example.com/x",
            "https://user@api.github.com/x",
            "https://user:pw@api.github.com/x",
            "https:///x",
            "ftp://github.com/x",
        ] {
            assert_eq!(check_host(bad, UPSTREAM_HOSTS), Err(NetError::HostNotAllowed), "{bad}");
        }
        assert!(hop_allowed("https://objects.githubusercontent.com/a?b", UPSTREAM_HOSTS));
        assert!(!hop_allowed("http://objects.githubusercontent.com/a", UPSTREAM_HOSTS));
        assert!(!hop_allowed("https://evil.example/a", UPSTREAM_HOSTS));
    }

    #[test]
    fn error_texts() {
        assert_eq!(NetError::HostNotAllowed.to_string(), "upstream host is not allowed");
        assert_eq!(NetError::RedirectLeftAllowedHosts.to_string(), "upstream redirect left the allowed hosts");
        assert_eq!(NetError::TooLarge.to_string(), "upstream answer is too large");
        assert_eq!(NetError::Unreachable("x".into()).to_string(), "upstream unreachable: x");
    }

    #[test]
    fn bounded_copy() {
        let mut sink = Vec::new();
        assert_eq!(copy_bounded(&mut &b"12345"[..], &mut sink, 5).unwrap(), 5);
        assert_eq!(sink, b"12345");
        let mut sink = Vec::new();
        assert_eq!(copy_bounded(&mut &b"123456"[..], &mut sink, 5), Err(NetError::TooLarge));
    }

    #[test]
    fn the_system_trust_store_loads() {
        if std::path::Path::new("/etc/ssl/certs").exists() {
            assert!(HttpsClient::upstream().is_ok());
        }
    }
}
