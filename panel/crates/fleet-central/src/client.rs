//! The central panel's HTTPS client to one linked node (`fleet_v2/client.py`).
//!
//! DNS is checked every time the pool opens a connection. Pin mode compares the leaf certificate
//! during the TLS handshake, before HTTP can send the bearer key or generation credentials.

use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use panel_fleet::central::{
    NodeClientFactory, NodeLink, CONNECT_TIMEOUT, MAX_RESPONSE_BYTES, REQUEST_TIMEOUT, TLS_MODES,
};
use panel_model::fleet::{ObservedGeneration, PushRequest, PushResponse};
use panel_model::protocols::BoxFuture;
use panel_model::seams::{CaptureItem, CapturePurpose, NodeClient, NodeError, SeamError};
use panel_model::validate::Model;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{CentralError, CentralResult};

const INVALID_URL: &str = "panel URL must be https://host[:port][/base-path]";
const PRIVATE_ADDRESS: &str = "private or local addresses need allow_private_address";
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const POOL_MAX_IDLE_PER_HOST: usize = 20;

/// `fleet_v2.client.validate_panel_url`: HTTPS only, without credentials, a query or a fragment.
/// The normalized form keeps the URL's authority and base path and strips trailing path slashes.
pub fn validate_panel_url(url: &str, allow_private: bool) -> CentralResult<String> {
    let text = panel_core::pytext::strip(url);
    let parsed = url::Url::parse(text).map_err(|_| CentralError::Invalid(INVALID_URL.into()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.query().is_some_and(|query| !query.is_empty())
        || parsed.fragment().is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(CentralError::Invalid(INVALID_URL.into()));
    }

    // `url::Url::username()` cannot distinguish no userinfo from an empty username. Python's
    // urlsplit can, and refuses both `https://@host` and `https://user@host`.
    let (_, remainder) = text.split_once("://").ok_or_else(|| CentralError::Invalid(INVALID_URL.into()))?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.contains('@') {
        return Err(CentralError::Invalid(INVALID_URL.into()));
    }
    let tail = &remainder[authority_end..];
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = &tail[..path_end];

    let private = match parsed.host().expect("checked above") {
        url::Host::Ipv4(address) => !is_global(address.into()),
        url::Host::Ipv6(address) => !is_global(address.into()),
        url::Host::Domain(host) => host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local"),
    };
    if private && !allow_private {
        return Err(CentralError::Invalid(PRIVATE_ADDRESS.into()));
    }
    Ok(format!("https://{authority}{}", path.trim_end_matches('/')))
}

/// Python's `ipaddress.is_global`, including its treatment of IPv4-mapped IPv6 addresses.
fn is_global(address: IpAddr) -> bool {
    panel_core::pytext::IpAddress::from(address).is_global()
}

/// `_public_address`: global and explicitly not multicast.
fn public_address(address: IpAddr) -> bool {
    let address = panel_core::pytext::IpAddress::from(address);
    address.is_global() && !address.is_multicast()
}

#[derive(Debug)]
struct AddressPolicyError;

impl fmt::Display for AddressPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PRIVATE_ADDRESS)
    }
}

impl std::error::Error for AddressPolicyError {}

/// Reject the whole answer, de-duplicate it in resolver order, and leave the original port for
/// reqwest to apply. In particular, never discard a private address and fall back to a public one.
fn checked_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, AddressPolicyError> {
    let mut checked = Vec::new();
    for address in addresses {
        if !allow_private && !public_address(address.ip()) {
            return Err(AddressPolicyError);
        }
        if !checked.contains(&address) {
            checked.push(address);
        }
    }
    if checked.is_empty() {
        return Err(AddressPolicyError);
    }
    Ok(checked)
}

#[derive(Debug, Clone, Copy)]
struct AddressResolver {
    allow_private: bool,
}

impl Resolve for AddressResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let addresses = match host.parse::<IpAddr>() {
                Ok(address) => vec![SocketAddr::new(address, 0)],
                Err(_) => tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
                    .collect(),
            };
            let addresses = checked_addresses(addresses, allow_private)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn sha256_hex(der: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(der);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

/// `None` is used only by the fingerprint probe: it deliberately accepts any chain and hostname,
/// while still authenticating the TLS handshake signatures. `Some` additionally requires the pin.
#[derive(Debug)]
struct LeafVerifier {
    expected_sha256: Option<String>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for LeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(expected) = &self.expected_sha256 {
            if sha256_hex(end_entity.as_ref()) != *expected {
                return Err(rustls::Error::General("pinned certificate mismatch".into()));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

static SYSTEM_ROOTS: LazyLock<Result<Arc<RootCertStore>, String>> = LazyLock::new(|| {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        // A malformed item in one OS store must not hide the other valid roots.
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        Err("could not load system certificate roots".into())
    } else {
        Ok(Arc::new(roots))
    }
});

fn tls_builder(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> CentralResult<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>> {
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| CentralError::Internal(error.to_string()))
}

fn pinned_tls_config(expected_sha256: Option<String>) -> CentralResult<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let supported = provider.signature_verification_algorithms;
    let mut config = tls_builder(provider)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LeafVerifier { expected_sha256, supported }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn verified_tls_config() -> CentralResult<ClientConfig> {
    verified_tls_with_roots(SYSTEM_ROOTS.clone().map_err(CentralError::Internal)?)
}

fn verified_tls_with_roots(roots: Arc<RootCertStore>) -> CentralResult<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = tls_builder(provider)?.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The explicit test-harness override. It applies only to a host with an exact `host=unix:path`
/// entry; every other origin retains normal DNS and TLS. Reqwest still emits the original Host.
#[cfg(all(unix, feature = "test-hooks"))]
fn test_node_socket(host: &str) -> CentralResult<Option<PathBuf>> {
    let Some(value) = std::env::var_os("PANEL_TEST_NODE_ROUTES") else {
        return Ok(None);
    };
    let value = value.to_str().ok_or_else(|| CentralError::Invalid("PANEL_TEST_NODE_ROUTES must be UTF-8".into()))?;
    for item in value.split(',').filter(|item| !item.is_empty()) {
        let Some((route_host, target)) = item.split_once('=') else {
            continue;
        };
        if route_host != host {
            continue;
        }
        let path = target.strip_prefix("unix:").filter(|path| !path.is_empty()).ok_or_else(|| {
            CentralError::Invalid(format!("PANEL_TEST_NODE_ROUTES: {item:?} is not host=unix:<path>"))
        })?;
        return Ok(Some(PathBuf::from(path)));
    }
    Ok(None)
}

/// A reusable bearer-authenticated client to one node's `/api/fleet/v2/*` routes.
pub struct NodeHttpClient {
    base_url: String,
    authorization: HeaderValue,
    http: reqwest::Client,
    blocked_literal: bool,
}

impl fmt::Debug for NodeHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeHttpClient").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

impl NodeHttpClient {
    /// Build a client in `verify` (system roots and WebPKI hostname checks) or `pin` mode.
    pub fn new(
        base_url: &str,
        api_key: &str,
        tls_verify: &str,
        pinned_sha256: Option<&str>,
        allow_private: bool,
    ) -> CentralResult<Self> {
        if !TLS_MODES.contains(&tls_verify) {
            return Err(CentralError::Invalid("tls_verify must be verify or pin".into()));
        }
        if tls_verify == "pin" && pinned_sha256.is_none_or(str::is_empty) {
            return Err(CentralError::Invalid("pin mode needs pinned_sha256".into()));
        }
        let base_url = validate_panel_url(base_url, allow_private)?;
        // Hyper bypasses its DNS resolver for numeric hosts. Gate those at call time as the
        // Python backend does, including multicast (permitted by URL-only validation).
        let parsed = url::Url::parse(&base_url).map_err(|_| CentralError::Invalid(INVALID_URL.into()))?;
        let literal = match parsed.host().expect("validated URL has a host") {
            url::Host::Ipv4(address) => Some(IpAddr::V4(address)),
            url::Host::Ipv6(address) => Some(IpAddr::V6(address)),
            url::Host::Domain(_) => None,
        };
        let blocked_literal = !allow_private && literal.is_some_and(|address| !public_address(address));
        #[cfg(all(unix, feature = "test-hooks"))]
        let mut base_url = base_url;
        #[cfg(all(unix, feature = "test-hooks"))]
        let host = url::Url::parse(&base_url)
            .map_err(|_| CentralError::Invalid(INVALID_URL.into()))?
            .host_str()
            .expect("validated URL has a host")
            .to_owned();

        let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
            .map_err(|_| CentralError::Invalid("API key cannot be used in an HTTP header".into()))?;
        authorization.set_sensitive(true);

        let mut builder = reqwest::Client::builder()
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .read_timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
            .dns_resolver(AddressResolver { allow_private });
        // Reqwest constructs its HTTPS connector even for a UDS/HTTP harness route. Always
        // supply the explicit provider, rather than relying on a process-global installation.
        let tls = match tls_verify {
            "verify" => verified_tls_config()?,
            "pin" => pinned_tls_config(Some(pinned_sha256.expect("checked above").to_lowercase()))?,
            _ => unreachable!("validated above"),
        };
        builder = builder.tls_backend_preconfigured(tls);

        #[cfg(all(unix, feature = "test-hooks"))]
        let test_socket = test_node_socket(&host)?;
        #[cfg(not(all(unix, feature = "test-hooks")))]
        let test_socket: Option<PathBuf> = None;

        if let Some(path) = test_socket {
            // The harness contract is deliberately plain HTTP over its private UDS. There is no
            // production fallback: only an exact, explicit environment route selects this branch.
            #[cfg(all(unix, feature = "test-hooks"))]
            {
                builder = builder.unix_socket(path);
                base_url = base_url.replacen("https://", "http://", 1);
            }
            #[cfg(not(all(unix, feature = "test-hooks")))]
            drop(path);
        }

        let http = builder.build().map_err(|error| CentralError::Internal(error.to_string()))?;
        Ok(Self { base_url, authorization, http, blocked_literal })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        timeout: Option<Duration>,
    ) -> Result<(u16, Map<String, Value>), NodeError> {
        if self.blocked_literal {
            return Err(NodeError::Unreachable("ConnectError".into()));
        }
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .header(AUTHORIZATION, self.authorization.clone());
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(panel_core::pyjson::compact_utf8(body));
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let mut response =
            request.send().await.map_err(|error| NodeError::Unreachable(transport_kind(&error).into()))?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            // Do not consume an authentication error body.
            return Err(NodeError::AuthFailed);
        }

        let mut content = Vec::new();
        while let Some(chunk) =
            response.chunk().await.map_err(|error| NodeError::Unreachable(transport_kind(&error).into()))?
        {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(content.len()) {
                return Err(NodeError::Rejected {
                    status,
                    code: Some("response_too_large".into()),
                    detail: String::new(),
                });
            }
            content.extend_from_slice(&chunk);
        }

        let value = if content.is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_slice(&content).unwrap_or(Value::Null)
        };
        let body = match value {
            Value::Object(body) => body,
            _ => Map::new(),
        };
        if status >= 400 {
            let code = body.get("code").and_then(Value::as_str).map(str::to_owned);
            let detail = body.get("detail").map(panel_model::pyrepr::str).unwrap_or_default();
            return Err(NodeError::Rejected { status, code, detail });
        }
        Ok((status, body))
    }
}

/// Keep only an error class, never reqwest's display text (which can contain request details).
fn transport_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        if error.is_connect() {
            "ConnectTimeout"
        } else {
            "ReadTimeout"
        }
    } else if error.is_connect() {
        "ConnectError"
    } else if error.is_body() || error.is_decode() {
        "ReadError"
    } else {
        "RequestError"
    }
}

impl NodeClient for NodeHttpClient {
    fn identity(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(
            async move { self.call(Method::GET, "/api/fleet/v2/identity", None, None).await.map(|(_, body)| body) },
        )
    }

    fn status(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move { self.call(Method::GET, "/api/fleet/v2/status", None, None).await.map(|(_, body)| body) })
    }

    fn inventory(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(
            async move { self.call(Method::GET, "/api/fleet/v2/inventory", None, None).await.map(|(_, body)| body) },
        )
    }

    fn metrics(&self, timeout: Duration) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.call(Method::GET, "/api/fleet/v2/metrics", None, Some(timeout)).await.map(|(_, body)| body)
        })
    }

    fn metrics_history<'a>(
        &'a self,
        series: &'a [String],
        range: &'a str,
        points: i64,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let query = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("series", &series.join(","))
                .append_pair("range", range)
                .append_pair("points", &points.to_string())
                .finish();
            self.call(Method::GET, &format!("/api/fleet/v2/metrics/history?{query}"), None, Some(timeout))
                .await
                .map(|(_, body)| body)
        })
    }

    fn metrics_summary<'a>(
        &'a self,
        range: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let query = url::form_urlencoded::Serializer::new(String::new()).append_pair("range", range).finish();
            self.call(Method::GET, &format!("/api/fleet/v2/metrics/summary?{query}"), None, Some(timeout))
                .await
                .map(|(_, body)| body)
        })
    }

    fn push<'a>(&'a self, request: &'a PushRequest) -> BoxFuture<'a, Result<(u16, PushResponse), NodeError>> {
        Box::pin(async move {
            let (status, body) =
                self.call(Method::PUT, "/api/fleet/v2/generation", Some(&request.wire()), None).await?;
            let response = PushResponse::validate(&Value::Object(body)).map_err(NodeError::InvalidAnswer)?;
            Ok((status, response))
        })
    }

    fn observed(&self) -> BoxFuture<'_, Result<ObservedGeneration, NodeError>> {
        Box::pin(async move {
            let (_, body) = self.call(Method::GET, "/api/fleet/v2/observed", None, None).await?;
            ObservedGeneration::validate(&Value::Object(body)).map_err(NodeError::InvalidAnswer)
        })
    }

    fn capture<'a>(
        &'a self,
        resources: &'a [CaptureItem],
        purpose: CapturePurpose,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let resources = resources
                .iter()
                .map(|item| json!({"protocol": &item.protocol, "runtime_username": &item.runtime_username}))
                .collect::<Vec<_>>();
            let mut body = Map::new();
            body.insert("resources".into(), Value::Array(resources));
            if purpose == CapturePurpose::Import {
                body.insert("purpose".into(), Value::String("import".into()));
            }
            self.call(Method::POST, "/api/fleet/v2/credentials/capture", Some(&Value::Object(body)), None)
                .await
                .map(|(_, body)| body)
        })
    }

    fn update_version<'a>(
        &'a self,
        component: &'a str,
        version: &'a str,
        expected_current: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let body = json!({"component": component, "version": version, "expected_current": expected_current});
            self.call(Method::POST, "/api/fleet/v2/versions/update", Some(&body), None).await.map(|(_, body)| body)
        })
    }

    fn check_versions(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            self.call(Method::POST, "/api/fleet/v2/versions/check", None, None).await.map(|(_, body)| body)
        })
    }

    fn unlink(&self) -> BoxFuture<'_, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move { self.call(Method::POST, "/api/fleet/v2/unlink", None, None).await.map(|(_, body)| body) })
    }

    fn exit_test<'a>(&'a self, spec: &'a Map<String, Value>) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let body = json!({"exit": spec});
            self.call(Method::POST, "/api/fleet/v2/exits/test", Some(&body), None).await.map(|(_, body)| body)
        })
    }

    fn geodata<'a>(
        &'a self,
        action: &'a str,
        body: Option<&'a Map<String, Value>>,
    ) -> BoxFuture<'a, Result<Map<String, Value>, NodeError>> {
        Box::pin(async move {
            let (method, path, body) = match action {
                "view" => (Method::GET, "/api/fleet/v2/geodata".into(), None),
                "codes" => (Method::GET, "/api/fleet/v2/geodata/codes".into(), None),
                "settings" => (
                    Method::PUT,
                    "/api/fleet/v2/geodata/settings".into(),
                    Some(Value::Object(body.cloned().unwrap_or_default())),
                ),
                _ => (Method::POST, format!("/api/fleet/v2/geodata/{action}"), None),
            };
            self.call(method, &path, body.as_ref(), None).await.map(|(_, body)| body)
        })
    }
}

/// The factory stored by `NodeLinkService`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeHttpFactory;

impl NodeClientFactory for NodeHttpFactory {
    fn client(&self, link: &NodeLink, api_key: &str) -> Result<Arc<dyn NodeClient>, SeamError> {
        let client = NodeHttpClient::new(
            &link.panel_url,
            api_key,
            &link.tls_verify,
            link.pinned_cert_sha256.as_deref(),
            link.allow_private_address,
        )?;
        Ok(Arc::new(client))
    }
}

/// Capture the lowercase SHA-256 of the leaf DER with an unverified-chain TLS handshake.
/// DNS, connection attempts and the handshake share the caller's deadline.
pub fn fingerprint(url: &str, timeout: Duration, allow_private: bool) -> CentralResult<String> {
    let url = validate_panel_url(url, allow_private)?;
    let parsed = url::Url::parse(&url).map_err(|_| CentralError::Invalid(INVALID_URL.into()))?;
    let host = match parsed.host().expect("validated URL has a host") {
        url::Host::Domain(host) => host.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    let port = parsed.port().unwrap_or(443);
    let server_name = ServerName::try_from(host.clone()).map_err(|_| CentralError::Invalid(INVALID_URL.into()))?;
    let deadline = Instant::now() + timeout;
    let addresses = fingerprint_addresses(&host, port, allow_private, deadline)?;
    let config = Arc::new(pinned_tls_config(None)?);

    let mut last_error = "ConnectError";
    for address in addresses {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else {
            return Err(NodeError::Unreachable("TimeoutError".into()).into());
        };
        match probe_certificate(address, server_name.clone(), config.clone(), remaining) {
            Ok(digest) => return Ok(digest),
            Err(kind) => last_error = kind,
        }
    }
    Err(NodeError::Unreachable(last_error.into()).into())
}

fn fingerprint_addresses(
    host: &str,
    port: u16,
    allow_private: bool,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, NodeError> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return checked_addresses([SocketAddr::new(address, port)], allow_private)
            .map_err(|_| NodeError::Unreachable("ConnectError".into()));
    }
    let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()) else {
        return Err(NodeError::Unreachable("TimeoutError".into()));
    };
    // std has no bounded getaddrinfo. A one-shot helper thread keeps the probe's public deadline;
    // the receiver is dropped on timeout and a late resolver answer is simply discarded.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let host = host.to_owned();
    std::thread::Builder::new()
        .name("node-fingerprint-dns".into())
        .spawn(move || {
            let result = (host.as_str(), port).to_socket_addrs().map(|addresses| addresses.collect::<Vec<_>>());
            let _ = sender.send(result);
        })
        .map_err(|_| NodeError::Unreachable("ConnectError".into()))?;
    let addresses = match receiver.recv_timeout(remaining) {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err(NodeError::Unreachable("ConnectError".into()));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Err(NodeError::Unreachable("TimeoutError".into())),
    };
    checked_addresses(addresses, allow_private).map_err(|_| NodeError::Unreachable("ConnectError".into()))
}

fn probe_certificate(
    address: SocketAddr,
    server_name: ServerName<'static>,
    config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<String, &'static str> {
    let deadline = Instant::now() + timeout;
    let stream = TcpStream::connect_timeout(&address, timeout).map_err(io_kind)?;
    stream.set_read_timeout(Some(timeout)).map_err(io_kind)?;
    stream.set_write_timeout(Some(timeout)).map_err(io_kind)?;
    let connection = ClientConnection::new(config, server_name).map_err(|_| "SSLError")?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        let remaining =
            deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero()).ok_or("TimeoutError")?;
        tls.sock.set_read_timeout(Some(remaining)).map_err(io_kind)?;
        tls.sock.set_write_timeout(Some(remaining)).map_err(io_kind)?;
        tls.conn.complete_io(&mut tls.sock).map_err(io_kind)?;
    }
    let certificate = tls.conn.peer_certificates().and_then(|certificates| certificates.first()).ok_or("SSLError")?;
    Ok(sha256_hex(certificate.as_ref()))
}

fn io_kind(error: std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "TimeoutError",
        std::io::ErrorKind::InvalidData => "SSLError",
        _ => "ConnectError",
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    use rustls::pki_types::PrivateKeyDer;
    use rustls::ServerConnection;

    use super::*;

    #[test]
    fn panel_urls_are_normalized_and_refused_like_python() {
        assert_eq!(validate_panel_url("  https://panel.example.com/  ", false).unwrap(), "https://panel.example.com");
        assert_eq!(
            validate_panel_url("https://panel.example.com/base///", false).unwrap(),
            "https://panel.example.com/base"
        );
        for bad in [
            "http://panel.example.com",
            "https://panel.example.com/?x=1",
            "https://panel.example.com/#fragment",
            "https://10.0.0.1",
            "https://127.0.0.1",
            "https://[::1]",
            "https://localhost",
            "https://node.local",
            "https://@panel.example.com",
            "https://:synthetic@panel.example.com",
        ] {
            assert!(validate_panel_url(bad, false).is_err(), "accepted {bad}");
        }
        assert_eq!(validate_panel_url("https://10.0.0.1:8443", true).unwrap(), "https://10.0.0.1:8443");
        assert_eq!(validate_panel_url("https://[::1]:8443/", true).unwrap(), "https://[::1]:8443");
        assert!(NodeHttpClient::new("https://node.example", "k", "pin", None, false).is_err());
        assert!(NodeHttpClient::new("https://node.example", "k", "skip", None, false).is_err());
    }

    #[test]
    fn address_policy_rejects_the_entire_answer() {
        let addresses =
            |values: &[&str]| values.iter().map(|value| value.parse::<SocketAddr>().unwrap()).collect::<Vec<_>>();
        for rejected in [
            &["127.0.0.1:0"][..],
            &["[::1]:0"][..],
            &["169.254.169.254:0"][..],
            &["224.0.0.1:0"][..],
            &["[::ffff:127.0.0.1]:0"][..],
            &["8.8.8.8:0", "10.0.0.1:0"][..],
        ] {
            assert!(checked_addresses(addresses(rejected), false).is_err(), "accepted {rejected:?}");
        }
        let deduplicated = checked_addresses(addresses(&["8.8.8.8:0", "8.8.8.8:0", "1.1.1.1:0"]), false).unwrap();
        assert_eq!(deduplicated, addresses(&["8.8.8.8:0", "1.1.1.1:0"]));
        assert!(checked_addresses(addresses(&["127.0.0.1:0", "224.0.0.1:0"]), true).is_ok());
        assert!(checked_addresses(Vec::new(), true).is_err());
    }

    struct Reply {
        status: u16,
        body: Vec<u8>,
        extra_headers: String,
        keep_alive: bool,
        delay: Duration,
    }

    impl Reply {
        fn json(status: u16, body: Value) -> Self {
            Self { status, body: body.to_string().into_bytes(), extra_headers: String::new(), keep_alive: false, delay: Duration::ZERO }
        }

        fn bytes(status: u16, body: Vec<u8>) -> Self {
            Self { status, body, extra_headers: String::new(), keep_alive: false, delay: Duration::ZERO }
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        request_line: String,
        headers: String,
        body: Vec<u8>,
        server_name: Option<String>,
    }

    struct TlsServer {
        url: String,
        pin: String,
        certificate: CertificateDer<'static>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        thread: JoinHandle<()>,
    }

    impl TlsServer {
        fn start(connections: usize, replies: Vec<Reply>) -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let pin = sha256_hex(cert.der().as_ref());
            let key = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .unwrap();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let config = Arc::new(config);

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("https://127.0.0.1:{}", listener.local_addr().unwrap().port());
            listener.set_nonblocking(true).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let server_requests = requests.clone();
            let thread = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut accepted = 0;
                let mut answered = 0;
                while accepted < connections && Instant::now() < deadline {
                    let (stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    accepted += 1;
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                    let connection = ServerConnection::new(config.clone()).unwrap();
                    let mut tls = StreamOwned::new(connection, stream);
                    while let Some(mut request) = read_request(&mut tls) {
                        request.server_name = tls.conn.server_name().map(str::to_owned);
                        server_requests.lock().unwrap().push(request);
                        let Some(reply) = replies.get(answered) else { break };
                        answered += 1;
                        if !reply.delay.is_zero() { std::thread::sleep(reply.delay); }
                        let head = format!(
                            "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: {}\r\n{}\r\n",
                            reply.status,
                            reply.body.len(),
                            if reply.keep_alive { "keep-alive" } else { "close" },
                            reply.extra_headers,
                        );
                        if tls.write_all(head.as_bytes()).and_then(|()| tls.write_all(&reply.body)).and_then(|()| tls.flush()).is_err() || !reply.keep_alive {
                            break;
                        }
                    }
                }
            });
            Self { url, pin, certificate: cert.der().clone(), requests, thread }
        }

        fn client(&self, key: &str) -> NodeHttpClient {
            NodeHttpClient::new(&self.url, key, "pin", Some(&self.pin), true).unwrap()
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn finish(self) {
            self.thread.join().unwrap();
        }
    }

    fn read_request(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> Option<RecordedRequest> {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        let header_end = loop {
            if let Some(end) = find_header_end(&bytes) {
                break end;
            }
            if bytes.len() > 64 * 1024 {
                return None;
            }
            let count = tls.read(&mut buffer).ok()?;
            if count == 0 {
                return None;
            }
            bytes.extend_from_slice(&buffer[..count]);
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while bytes.len() < body_start + content_length {
            let count = tls.read(&mut buffer).ok()?;
            if count == 0 {
                return None;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Some(RecordedRequest {
            request_line: headers.lines().next().unwrap_or_default().to_owned(),
            headers,
            body: bytes[body_start..body_start + content_length].to_vec(),
            server_name: None,
        })
    }

    fn find_header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn observed(generation: i64, state: &str) -> Value {
        json!({
            "applied_generation": generation,
            "digest": "d",
            "reconcile_state": state,
            "resources": [],
            "reported_at": 1
        })
    }

    #[test]
    fn fingerprint_reads_the_real_leaf_der() {
        let server = TlsServer::start(1, Vec::new());
        let digest = fingerprint(&server.url, Duration::from_secs(5), true).unwrap();
        assert_eq!(digest, server.pin);
        assert!(server.requests().is_empty());
        server.finish();
    }

    #[tokio::test]
    async fn pin_match_accepts_and_mismatch_sends_no_http() {
        let server = TlsServer::start(2, vec![Reply::json(200, json!({"guid": "g"}))]);
        let body = server.client("pc_k").identity().await.unwrap();
        assert_eq!(body.get("guid").and_then(Value::as_str), Some("g"));

        let bad = NodeHttpClient::new(&server.url, "super-secret-key", "pin", Some(&"0".repeat(64)), true).unwrap();
        let error = bad.identity().await.unwrap_err();
        assert!(matches!(&error, NodeError::Unreachable(_)));
        assert!(!error.to_string().contains("super-secret-key"));

        let requests = server.requests();
        server.finish();
        assert_eq!(requests.len(), 1, "the mismatched peer received an HTTP request");
        assert_eq!(requests[0].request_line, "GET /api/fleet/v2/identity HTTP/1.1");
        assert!(requests[0].headers.to_ascii_lowercase().contains("authorization: bearer pc_k"));
    }

    #[tokio::test]
    async fn verify_refuses_untrusted_leaf_before_sending_http() {
        let server = TlsServer::start(1, Vec::new());
        let client = NodeHttpClient::new(&server.url, "untrusted-secret", "verify", None, true).unwrap();
        assert!(matches!(client.identity().await, Err(NodeError::Unreachable(_))));
        assert!(server.requests().is_empty());
        server.finish();
    }

    #[tokio::test]
    async fn verify_accepts_trusted_leaf_but_rejects_the_wrong_hostname() {
        let server = TlsServer::start(2, vec![Reply::json(200, json!({"guid": "verified"}))]);
        let mut roots = RootCertStore::empty();
        roots.add(server.certificate.clone()).unwrap();
        let config = verified_tls_with_roots(Arc::new(roots)).unwrap();
        let mut client = server.client("verified-key");
        client.http = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .dns_resolver(AddressResolver { allow_private: true })
            .tls_backend_preconfigured(config)
            .build()
            .unwrap();
        assert_eq!(client.identity().await.unwrap()["guid"], "verified");
        client.base_url = server.url.replace("127.0.0.1", "localhost");
        assert!(matches!(client.identity().await, Err(NodeError::Unreachable(_))));
        assert_eq!(server.requests().len(), 1, "wrong hostname received an HTTP bearer");
        server.finish();
    }

    #[tokio::test]
    async fn private_dns_is_rejected_before_tcp_in_both_tls_modes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://localhost.:{}", listener.local_addr().unwrap().port());
        for mode in ["verify", "pin"] {
            let client = NodeHttpClient::new(&url, "private-secret", mode, Some(&"0".repeat(64)), false).unwrap();
            assert!(matches!(client.identity().await, Err(NodeError::Unreachable(_))));
            assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            let multicast =
                NodeHttpClient::new("https://224.0.0.1", "private-secret", mode, Some(&"0".repeat(64)), false).unwrap();
            assert!(matches!(multicast.identity().await, Err(NodeError::Unreachable(_))));
        }
        assert!(fingerprint(&url, Duration::from_secs(5), false).is_err());
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn statuses_invalid_reports_and_large_bodies_are_typed() {
        let server = TlsServer::start(
            6,
            vec![
                Reply::json(401, json!({"detail": "bad key"})),
                Reply::json(403, json!({"detail": "bad scope"})),
                Reply::json(409, json!({"detail": "generation is stale", "code": "stale_generation"})),
                Reply::bytes(500, b"internal error".to_vec()),
                Reply::json(200, json!({})),
                Reply::bytes(200, vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            ],
        );
        let client = server.client("k");
        assert_eq!(client.identity().await.unwrap_err(), NodeError::AuthFailed);
        assert_eq!(client.identity().await.unwrap_err(), NodeError::AuthFailed);
        assert_eq!(
            client.identity().await.unwrap_err(),
            NodeError::Rejected {
                status: 409,
                code: Some("stale_generation".into()),
                detail: "generation is stale".into()
            }
        );
        assert_eq!(
            client.identity().await.unwrap_err(),
            NodeError::Rejected { status: 500, code: None, detail: String::new() }
        );
        assert!(matches!(client.observed().await.unwrap_err(), NodeError::InvalidAnswer(_)));
        assert_eq!(
            client.identity().await.unwrap_err(),
            NodeError::Rejected { status: 200, code: Some("response_too_large".into()), detail: String::new() }
        );
        server.finish();
    }

    #[tokio::test]
    async fn reports_and_request_payloads_follow_the_wire_contract() {
        let server = TlsServer::start(
            5,
            vec![
                Reply::json(202, json!({"observed": observed(1, "applying"), "credentials": {}})),
                Reply::json(200, observed(0, "idle")),
                Reply::json(200, json!({"credentials": {"naive:alice": "s3cr3t"}})),
                Reply::json(200, json!({"component": "telemt"})),
                Reply::json(200, json!({"series": {}})),
            ],
        );
        let client = server.client("k");
        let push = PushRequest::validate(&json!({
            "expected_guid": "n",
            "generation": {
                "node_guid": "n", "master_guid": "m", "generation": 1,
                "previous_generation": 0, "created_at": 1, "created_by": "c", "resources": []
            },
            "secrets": {}
        }))
        .unwrap();
        let (status, response) = client.push(&push).await.unwrap();
        assert_eq!(status, 202);
        assert_eq!(response.observed.applied_generation, 1);
        assert_eq!(response.observed.reconcile_state.as_str(), "applying");
        let observed = client.observed().await.unwrap();
        assert_eq!(observed.applied_generation, 0);
        assert_eq!(observed.reconcile_state.as_str(), "idle");

        let items = [CaptureItem { protocol: "naive".into(), runtime_username: "alice".into() }];
        let captured = client.capture(&items, CapturePurpose::Escrow).await.unwrap();
        assert_eq!(captured["credentials"]["naive:alice"], "s3cr3t");
        client.update_version("telemt", "1.2.3", Some("1.2.2")).await.unwrap();
        client.metrics_history(&["cpu".into(), "mem".into()], "1 h", 60, Duration::from_secs(10)).await.unwrap();

        let requests = server.requests();
        server.finish();
        assert_eq!(requests[0].request_line, "PUT /api/fleet/v2/generation HTTP/1.1");
        assert_eq!(serde_json::from_slice::<Value>(&requests[0].body).unwrap()["expected_guid"], "n");
        assert_eq!(requests[1].request_line, "GET /api/fleet/v2/observed HTTP/1.1");
        assert_eq!(requests[2].request_line, "POST /api/fleet/v2/credentials/capture HTTP/1.1");
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[2].body).unwrap(),
            json!({"resources": [{"protocol": "naive", "runtime_username": "alice"}]})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[3].body).unwrap(),
            json!({"component": "telemt", "version": "1.2.3", "expected_current": "1.2.2"})
        );
        assert_eq!(
            requests[4].request_line,
            "GET /api/fleet/v2/metrics/history?series=cpu%2Cmem&range=1+h&points=60 HTTP/1.1"
        );
    }

    include!("client_native_tests.rs");
}
