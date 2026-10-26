//! Ask the upstream projects what they published (`version_agent/upstream.py`): GitHub Releases
//! for Xray-core, mieru, Caddy, Telemt, TrustTunnel and this project, the GitHub tags of
//! amneziawg-go, the ghcr.io and Docker Hub registries for image digests. Fixed hosts, bounded
//! bodies, no token, and a candidate only when the publisher also published a digest.
//!
//! Probes and candidates are JSON objects, the shapes the agent caches in its state.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use pc_host::net::{ClientOptions, HttpsClient, NetError, UPSTREAM_HOSTS};
use serde_json::{json, Map, Value};

use crate::catalog::{is_dotted, is_hex40, is_version};

pub const MAX_JSON: u64 = 16 * 1024 * 1024;
pub const MAX_DIGEST_FILE: u64 = 4096;
pub const MAX_MANIFEST: u64 = 64 * 1024;
pub const MAX_TOKEN: u64 = 16 * 1024;
/// `SHA256SUMS` lists three files today; a future release may list more.
pub const MAX_SUMS_FILE: u64 = 16 * 1024;
pub const MAX_CANDIDATES: usize = 6;
pub const NAIVE_CANDIDATES: usize = 3;
pub const MAX_TELEMT_BINARY: i64 = 64 * 1024 * 1024;
pub const MAX_TRUSTTUNNEL_ARCHIVE: i64 = 128 * 1024 * 1024;
/// `COMPONENTS`: the order `check_all` probes in.
pub const COMPONENTS: [&str; 7] = ["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"];
pub const OPTIONAL_COMPONENTS: [&str; 2] = ["amneziawg", "trusttunnel"];
pub const TELEMT_REPOSITORY: &str = "samnet-dev/mtproxymax-telemt";
pub const TELEMT_UPSTREAM_REPOSITORY: &str = "telemt/telemt";
pub const TELEMT_BINARY_ASSET: &str = "telemt";
pub const AMNEZIAWG_REPOSITORY: &str = "amnezia-vpn/amneziawg-go";
pub const TRUSTTUNNEL_REPOSITORY: &str = "TrustTunnel/TrustTunnel";
pub const PANEL_REPOSITORY: &str = "dubr1k/proxy-control";
pub const PANEL_SUMS_ASSET: &str = "SHA256SUMS";
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.v2+json";

/// `UpstreamError`: the upstream answered something the agent will not act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamError(pub String);

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UpstreamError {}

fn fail<T>(message: impl Into<String>) -> Result<T, UpstreamError> {
    Err(UpstreamError(message.into()))
}

/// What a fetch returns: `(status, {Title-Case: value}, body)`; a non-2xx answer has no body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fetched {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Fetched {
    pub fn ok(body: impl Into<Vec<u8>>) -> Fetched {
        Fetched { status: 200, headers: BTreeMap::new(), body: body.into() }
    }
}

/// `Fetcher`: `(url, headers, maximum) -> (status, headers, body)`.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, headers: &[(&str, &str)], maximum: u64) -> Result<Fetched, UpstreamError>;
}

impl<F> Fetcher for F
where
    F: Fn(&str, &[(&str, &str)], u64) -> Result<Fetched, UpstreamError> + Send + Sync,
{
    fn fetch(&self, url: &str, headers: &[(&str, &str)], maximum: u64) -> Result<Fetched, UpstreamError> {
        self(url, headers, maximum)
    }
}

/// `fetch_https`: GET over HTTPS on the upstream allow-list, every redirect hop checked.
#[derive(Default)]
pub struct HttpsFetcher {
    client: OnceLock<Result<HttpsClient, String>>,
}

impl HttpsFetcher {
    pub fn new() -> HttpsFetcher {
        HttpsFetcher::default()
    }

    fn client(&self) -> Result<&HttpsClient, UpstreamError> {
        match self.client.get_or_init(|| HttpsClient::upstream().map_err(|err| err.to_string())) {
            Ok(client) => Ok(client),
            Err(message) => Err(UpstreamError(message.clone())),
        }
    }
}

impl Fetcher for HttpsFetcher {
    fn fetch(&self, url: &str, headers: &[(&str, &str)], maximum: u64) -> Result<Fetched, UpstreamError> {
        // `open_allowed` checks the host before it builds anything.
        pc_host::net::check_host(url, UPSTREAM_HOSTS).map_err(|err| UpstreamError(err.to_string()))?;
        let response =
            self.client()?.get(url, UPSTREAM_HOSTS, headers, maximum).map_err(|err| UpstreamError(err.to_string()))?;
        Ok(Fetched { status: response.head.status, headers: response.head.headers, body: response.body })
    }
}

/// Why an artifact download failed (`service._download`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadError {
    /// An `UpdateError` with this text.
    Refused(String),
    /// The network failed (urllib's `URLError`): the caller reports `<component> update failed`.
    Unreachable(String),
}

/// `_download(url, maximum=…)`: a catalog artifact may redirect only within its own host; an
/// upstream release asset may move within the upstream allow-list. Every hop is checked.
pub fn download_artifact(url: &str, maximum: u64) -> Result<Vec<u8>, DownloadError> {
    let host = pc_host::url::split(url).hostname();
    let mut allowed: Vec<&str> = host.as_deref().into_iter().collect();
    if host.as_deref().is_some_and(|h| UPSTREAM_HOSTS.contains(&h)) {
        allowed.extend_from_slice(UPSTREAM_HOSTS);
    }
    let options = ClientOptions { timeout: Duration::from_secs(120), ..ClientOptions::default() };
    let client = HttpsClient::new(options).map_err(|err| DownloadError::Unreachable(err.to_string()))?;
    let mut content = Vec::new();
    match client.download(url, &allowed, &[], maximum, &mut content) {
        Ok(head) if (200..300).contains(&head.status) => Ok(content),
        Ok(head) => Err(DownloadError::Refused(format!("artifact download failed: HTTP {}", head.status))),
        Err(NetError::RedirectLeftAllowedHosts) => {
            Err(DownloadError::Refused("artifact redirect left the catalog host".into()))
        }
        Err(NetError::TooLarge) => Err(DownloadError::Refused("artifact is too large".into())),
        Err(NetError::HostNotAllowed) => Err(DownloadError::Refused(NetError::HostNotAllowed.to_string())),
        Err(NetError::Unreachable(detail)) => Err(DownloadError::Unreachable(detail)),
    }
}

// --- versions -----------------------------------------------------------------------------

/// A non-negative integer of a version core, compared numerically at any length.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Number(String);

impl Number {
    fn of(piece: &str) -> Number {
        if crate::py::is_digits(piece) {
            let trimmed = piece.trim_start_matches('0');
            Number(if trimmed.is_empty() { "0".into() } else { trimmed.into() })
        } else {
            Number("0".into())
        }
    }
}

impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.len().cmp(&other.0.len()).then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `_parts(version)`: the numeric core (non-digit pieces count as 0) and the `-suffix`.
fn parts(version: &str) -> (Vec<Number>, &str) {
    let (core, suffix) = version.split_once('-').unwrap_or((version, ""));
    (core.split('.').map(Number::of).collect(), suffix)
}

/// `compare_versions(a, b)`: numeric dotted compare; a `-suffix` (pre-release) sorts below the
/// bare version, two suffixes compare as strings.
pub fn compare_versions(a: &str, b: &str) -> i32 {
    let (mut na, sa) = parts(a);
    let (mut nb, sb) = parts(b);
    let width = na.len().max(nb.len());
    na.resize(width, Number("0".into()));
    nb.resize(width, Number("0".into()));
    match na.cmp(&nb) {
        Ordering::Greater => return 1,
        Ordering::Less => return -1,
        Ordering::Equal => {}
    }
    if sa == sb {
        0
    } else if sa.is_empty() || (!sb.is_empty() && sa > sb) {
        1
    } else {
        -1
    }
}

/// `sort(key=_parts, reverse=True)` (stable).
fn sort_by_parts_desc<T>(items: &mut [T], version: impl Fn(&T) -> &str) {
    items.sort_by(|a, b| {
        let (na, sa) = parts(version(a));
        let (nb, sb) = parts(version(b));
        (nb, sb).cmp(&(na, sa))
    });
}

// --- parsers ------------------------------------------------------------------------------

fn is_hex64(text: &str) -> bool {
    crate::catalog::is_sha256(text)
}

/// `parse_dgst`: the `SHA2-256=` (or `SHA256=`) line of an Xray `.dgst` file.
pub fn parse_dgst(text: &str) -> Result<String, UpstreamError> {
    for line in crate::py::splitlines(text) {
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        let value = crate::py::strip(value).to_lowercase();
        if matches!(crate::py::strip(key), "SHA2-256" | "SHA256") && is_hex64(&value) {
            return Ok(value);
        }
    }
    fail("no SHA2-256 line in .dgst")
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `\b([0-9a-f]{64})\b` searched in the lower-cased text.
fn search_hex64(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut start = 0;
    while start + 64 <= chars.len() {
        let before_ok = start == 0 || !word_char(chars[start - 1]);
        let run = &chars[start..start + 64];
        let after_ok = start + 64 == chars.len() || !word_char(chars[start + 64]);
        if before_ok && after_ok && run.iter().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Some(run.iter().collect());
        }
        start += 1;
    }
    None
}

/// `parse_sha256_txt`: the first SHA-256 of a mieru `.sha256.txt`.
pub fn parse_sha256_txt(text: &str) -> Result<String, UpstreamError> {
    search_hex64(&text.to_lowercase()).ok_or_else(|| UpstreamError("no SHA-256 in .sha256.txt".into()))
}

/// `parse_sha256sums`: the digest of `filename` from a `sha256sum` listing.
pub fn parse_sha256sums(text: &str, filename: &str) -> Result<String, UpstreamError> {
    for line in crate::py::splitlines(text) {
        let line = crate::py::strip(line);
        let (digest, name) = line.split_once(' ').unwrap_or((line, ""));
        let name = crate::py::strip(name);
        let name = name.strip_prefix('*').unwrap_or(name);
        if name == filename {
            let digest = crate::py::strip(digest).to_lowercase();
            if is_hex64(&digest) {
                return Ok(digest);
            }
            return fail(format!("SHA256SUMS line for {filename} is not a SHA-256"));
        }
    }
    fail(format!("no SHA256SUMS line for {filename}"))
}

// --- requests -----------------------------------------------------------------------------

fn json_of(fetcher: &dyn Fetcher, url: &str, maximum: u64, headers: &[(&str, &str)]) -> Result<Value, UpstreamError> {
    let answer = fetcher.fetch(url, headers, maximum)?;
    if answer.status != 200 {
        return fail(format!("upstream answered {} for {}", answer.status, pc_host::url::split(url).path));
    }
    serde_json::from_slice(&answer.body).map_err(|_| UpstreamError("upstream answer is not JSON".into()))
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> &'a str {
    headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str()).unwrap_or("")
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(is_hex64)
}

struct Release {
    tag: String,
    version: String,
    published_at: Value,
    /// `{asset name: browser_download_url}`, the last asset of a name winning.
    assets: BTreeMap<String, Value>,
}

fn published(item: &Map<String, Value>) -> Value {
    match item.get("published_at") {
        Some(Value::String(text)) => Value::String(text.clone()),
        _ => Value::Null,
    }
}

fn get_truthy(item: &Map<String, Value>, key: &str) -> bool {
    item.get(key).is_some_and(crate::py::truthy)
}

fn list_of(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// `_releases`: the repository's last ten releases, newest first; drafts never count, a
/// pre-release only where asked.
fn releases(fetcher: &dyn Fetcher, repository: &str, prereleases: bool) -> Result<Vec<Release>, UpstreamError> {
    let items =
        json_of(fetcher, &format!("https://api.github.com/repos/{repository}/releases?per_page=10"), MAX_JSON, &[])?;
    let Value::Array(items) = items else {
        return fail("releases answer is not a list");
    };
    let mut result = Vec::new();
    for item in &items {
        let Some(item) = item.as_object() else { continue };
        if get_truthy(item, "draft") || (get_truthy(item, "prerelease") && !prereleases) {
            continue;
        }
        let Some(tag) = item.get("tag_name").map_or(Some(String::new()), crate::py::scalar_text) else { continue };
        let version = tag.strip_prefix('v').unwrap_or(&tag).to_string();
        if !is_version(&version) {
            continue;
        }
        let mut assets = BTreeMap::new();
        for asset in list_of(item.get("assets")) {
            if let Some(asset) = asset.as_object() {
                if let Some(Value::String(name)) = asset.get("name") {
                    assets.insert(name.clone(), asset.get("browser_download_url").cloned().unwrap_or(Value::Null));
                }
            }
        }
        result.push(Release { tag, version, published_at: published(item), assets });
    }
    sort_by_parts_desc(&mut result, |release| &release.version);
    Ok(result)
}

/// `_asset_url`: the asset's URL, which must be the release download of its own repository.
fn asset_url(assets: &BTreeMap<String, Value>, name: &str, repository: &str) -> Result<Option<String>, UpstreamError> {
    let Some(Value::String(url)) = assets.get(name) else {
        return Ok(None);
    };
    let parts = pc_host::url::split(url);
    let allowed = parts.scheme == "https"
        && parts.hostname().as_deref() == Some("github.com")
        && !parts.username().is_some_and(|u| !u.is_empty())
        && !parts.password().is_some_and(|p| !p.is_empty())
        && parts.query.is_empty()
        && parts.fragment.is_empty()
        && parts.path.starts_with(&format!("/{repository}/releases/download/"));
    if !allowed {
        return fail("asset URL is not the release download of its repository");
    }
    Ok(Some(url.clone()))
}

fn candidate_version(candidate: &Value) -> &str {
    candidate.get("version").and_then(Value::as_str).unwrap_or("")
}

/// `_probe`: `installable` when a candidate newer than the installed version exists.
fn probe(latest: Value, current: Option<&str>, candidates: Vec<Value>, reason: Option<&str>) -> Value {
    let newer =
        candidates.iter().any(|c| current.is_none_or(|current| compare_versions(candidate_version(c), current) > 0));
    json!({"latest": latest, "installable": newer, "reason": if newer { None } else { reason }, "candidates": candidates})
}

fn nothing(reason: &str) -> Value {
    json!({"latest": null, "installable": false, "reason": reason, "candidates": []})
}

struct BinarySource<'a> {
    repository: &'a str,
    asset: &'a dyn Fn(&str) -> String,
    digest_suffix: &'a str,
    parse: fn(&str) -> Result<String, UpstreamError>,
    archive: Value,
    prereleases: bool,
}

/// `_github_binary`.
fn github_binary(
    fetcher: &dyn Fetcher,
    current: Option<&str>,
    source: &BinarySource<'_>,
) -> Result<Value, UpstreamError> {
    let releases = releases(fetcher, source.repository, source.prereleases)?;
    let Some(first) = releases.first() else {
        return Ok(nothing("no_releases"));
    };
    let latest = first.version.clone();
    let mut candidates = Vec::new();
    let mut reason: Option<&str> = None;
    for release in &releases {
        if candidates.len() >= MAX_CANDIDATES {
            break;
        }
        let order = current.map_or(1, |current| compare_versions(&release.version, current));
        if order == 0 {
            continue;
        }
        // Only a newer release without a digest is worth a reason on the screen.
        let missing = if order > 0 { Some("no_published_digest") } else { None };
        let name = (source.asset)(&release.version);
        let url = asset_url(&release.assets, &name, source.repository)?;
        let digest_url = asset_url(&release.assets, &format!("{name}{}", source.digest_suffix), source.repository)?;
        let (Some(url), Some(digest_url)) = (url, digest_url) else {
            reason = reason.or(missing);
            continue;
        };
        let answer = fetcher.fetch(&digest_url, &[], MAX_DIGEST_FILE)?;
        if answer.status != 200 {
            reason = reason.or(missing);
            continue;
        }
        let Ok(digest) = (source.parse)(&String::from_utf8_lossy(&answer.body)) else {
            reason = reason.or(missing);
            continue;
        };
        candidates.push(json!({
            "version": release.version, "tag": release.tag, "kind": "binary", "source": "upstream", "url": url,
            "sha256": digest, "archive": source.archive, "published_at": release.published_at,
        }));
    }
    Ok(probe(Value::String(latest), current, candidates, reason))
}

/// `_token`: an anonymous pull token of a registry.
fn token(fetcher: &dyn Fetcher, url: &str) -> Result<String, UpstreamError> {
    match json_of(fetcher, url, MAX_TOKEN, &[])?.get("token") {
        Some(Value::String(token)) if !token.is_empty() => Ok(token.clone()),
        _ => fail("registry did not issue a pull token"),
    }
}

/// `_registry_digest`: the `Docker-Content-Digest` of a manifest.
fn registry_digest(
    fetcher: &dyn Fetcher,
    registry: &str,
    repository: &str,
    tag: &str,
    token: &str,
) -> Result<String, UpstreamError> {
    let authorization = format!("Bearer {token}");
    let headers = [("Authorization", authorization.as_str()), ("Accept", MANIFEST_ACCEPT)];
    let answer =
        fetcher.fetch(&format!("https://{registry}/v2/{repository}/manifests/{tag}"), &headers, MAX_MANIFEST)?;
    let digest = header(&answer.headers, "Docker-Content-Digest");
    if answer.status != 200 || !is_digest(digest) {
        return fail("registry did not answer with a content digest");
    }
    Ok(digest.to_string())
}

/// `_IMAGE_TAG`: `<dotted digits>` with an optional `-<6..12 hex>`; the version part.
fn image_tag_version(tag: &str) -> Option<&str> {
    let (version, commit) = tag.split_once('-').unwrap_or((tag, ""));
    let commit_ok = !tag.contains('-')
        || ((6..=12).contains(&commit.len()) && commit.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    (is_dotted(version) && commit_ok).then_some(version)
}

/// `_telemt_builds`: Telemt releases that ship the binary with a published SHA-256.
fn telemt_builds(fetcher: &dyn Fetcher) -> Result<Vec<Value>, UpstreamError> {
    let repository = TELEMT_UPSTREAM_REPOSITORY;
    let items =
        json_of(fetcher, &format!("https://api.github.com/repos/{repository}/releases?per_page=10"), MAX_JSON, &[])?;
    let Value::Array(items) = items else {
        return fail("releases answer is not a list");
    };
    let mut result = Vec::new();
    for item in &items {
        let Some(item) = item.as_object() else { continue };
        if get_truthy(item, "draft") || get_truthy(item, "prerelease") {
            continue;
        }
        let Some(tag) = item.get("tag_name").and_then(Value::as_str).filter(|t| is_dotted(t)) else { continue };
        let asset = list_of(item.get("assets"))
            .iter()
            .filter_map(Value::as_object)
            .find(|a| a.get("name").and_then(Value::as_str) == Some(TELEMT_BINARY_ASSET));
        let Some(asset) = asset else { continue };
        let digest = asset.get("digest").and_then(Value::as_str).filter(|d| is_digest(d));
        let size = asset.get("size").and_then(crate::py::as_strict_int);
        let (Some(digest), Some(_)) = (digest, size.filter(|s| (1..=MAX_TELEMT_BINARY).contains(s))) else { continue };
        let mut single = BTreeMap::new();
        single
            .insert(TELEMT_BINARY_ASSET.to_string(), asset.get("browser_download_url").cloned().unwrap_or(Value::Null));
        let url = asset_url(&single, TELEMT_BINARY_ASSET, repository)?;
        let expected = format!("https://github.com/{repository}/releases/download/{tag}/{TELEMT_BINARY_ASSET}");
        if url.as_deref() != Some(expected.as_str()) {
            return fail("asset URL is not the release download of its repository");
        }
        result.push(json!({
            "version": tag, "tag": tag, "kind": "build", "source": "upstream", "url": expected,
            "sha256": &digest[7..], "published_at": published(item),
        }));
    }
    Ok(result)
}

/// `_telemt`: registry images of mtproxymax-telemt, plus `build` candidates of Telemt's own
/// releases on top of the newest registry image.
fn telemt(fetcher: &dyn Fetcher, current: Option<&str>) -> Result<Value, UpstreamError> {
    let repository = TELEMT_REPOSITORY;
    let token = token(fetcher, &format!("https://ghcr.io/token?scope=repository:{repository}:pull"))?;
    let authorization = format!("Bearer {token}");
    let listed = json_of(
        fetcher,
        &format!("https://ghcr.io/v2/{repository}/tags/list?n=100"),
        MAX_JSON,
        &[("Authorization", authorization.as_str())],
    )?;
    // version → its last tag, in the order versions first appear (a Python dict).
    let mut by_version: Vec<(String, String)> = Vec::new();
    for tag in list_of(listed.get("tags")) {
        let Some(tag) = tag.as_str() else { continue };
        if let Some(version) = image_tag_version(tag) {
            match by_version.iter_mut().find(|(known, _)| known == version) {
                Some(entry) => entry.1 = tag.to_string(),
                None => by_version.push((version.to_string(), tag.to_string())),
            }
        }
    }
    let mut versions: Vec<String> = by_version.iter().map(|(version, _)| version.clone()).collect();
    versions.sort_by(|a, b| parts(b).0.cmp(&parts(a).0));
    let Some(newest) = versions.first().cloned() else {
        return Ok(nothing("no_releases"));
    };
    let tag_of =
        |version: &str| by_version.iter().find(|(v, _)| v == version).map(|(_, t)| t.clone()).unwrap_or_default();
    let mut candidates: Vec<Value> = Vec::new();
    let mut newest_image: Option<String> = None;
    for version in &versions {
        if candidates.len() >= MAX_CANDIDATES {
            break;
        }
        let order = current.map_or(1, |current| compare_versions(version, current));
        if order == 0 && *version != newest {
            continue;
        }
        let digest = match registry_digest(fetcher, "ghcr.io", repository, &tag_of(version), &token) {
            Ok(digest) => digest,
            Err(err) if order > 0 => return Err(err),
            // An older image the registry no longer answers for is just not offered.
            Err(_) => continue,
        };
        if *version == newest {
            newest_image = Some(format!("ghcr.io/{repository}@{digest}"));
        }
        if order == 0 {
            continue;
        }
        candidates.push(json!({
            "version": version, "tag": tag_of(version), "kind": "image", "source": "upstream",
            "image": format!("ghcr.io/{repository}@{digest}"), "published_at": null,
        }));
    }
    let mut latest = newest.clone();
    let mut last_error = None;
    if let Some(newest_image) = newest_image {
        let builds = match telemt_builds(fetcher) {
            Ok(builds) => builds,
            Err(err) => {
                last_error = Some(err.0);
                Vec::new()
            }
        };
        for mut build in builds {
            let version = candidate_version(&build).to_string();
            if compare_versions(&version, &latest) > 0 {
                latest = version.clone();
            }
            let order = current.map_or(1, |current| compare_versions(&version, current));
            // The registry image of the same version wins over a build of it.
            if order == 0 || by_version.iter().any(|(known, _)| *known == version) {
                continue;
            }
            build["base_image"] = Value::String(newest_image.clone());
            candidates.push(build);
        }
        sort_by_parts_desc(&mut candidates, |c| candidate_version(c));
        candidates.truncate(MAX_CANDIDATES);
    }
    let mut result = probe(Value::String(latest), current, candidates, None);
    if let Some(error) = last_error.filter(|e| !e.is_empty()) {
        result["last_error"] = Value::String(error);
    }
    Ok(result)
}

/// `_naive`: Caddy releases built on the host with the pinned builder image and forwardproxy.
fn naive(fetcher: &dyn Fetcher, current: Option<&str>) -> Result<Value, UpstreamError> {
    let releases = releases(fetcher, "caddyserver/caddy", false)?;
    let Some(first) = releases.first() else {
        return Ok(nothing("no_releases"));
    };
    let picked: Vec<&Release> = releases
        .iter()
        .filter(|r| current.is_none_or(|current| compare_versions(&r.version, current) != 0))
        .take(NAIVE_CANDIDATES)
        .collect();
    if picked.is_empty() {
        return Ok(json!({"latest": first.version, "installable": false, "reason": null, "candidates": []}));
    }
    // NaiveProxy's forwardproxy lives on the `naive` branch.
    let head = json_of(fetcher, "https://api.github.com/repos/klzgrad/forwardproxy/commits/naive", MAX_JSON, &[])?;
    let Some(commit) = head.get("sha").and_then(Value::as_str).filter(|c| is_hex40(c)) else {
        return fail("forwardproxy commit is missing");
    };
    let token =
        token(fetcher, "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/caddy:pull")?;
    let mut candidates = Vec::new();
    for release in picked {
        let tag = format!("{}-builder", release.version);
        let digest = match registry_digest(fetcher, "registry-1.docker.io", "library/caddy", &tag, &token) {
            Ok(digest) => digest,
            Err(err) if current.is_none_or(|current| compare_versions(&release.version, current) > 0) => {
                return Err(err)
            }
            // No builder image for an older Caddy: not offered.
            Err(_) => continue,
        };
        candidates.push(json!({
            "version": release.version, "tag": release.tag, "kind": "build", "source": "upstream",
            "published_at": release.published_at,
            "build": {"caddy_version": release.version, "builder_image": format!("caddy:{}-builder@{digest}", release.version),
                      "forwardproxy_commit": commit},
        }));
    }
    Ok(probe(Value::String(first.version.clone()), current, candidates, None))
}

/// `_panel`: this project's releases (forward only): the archive plus its `SHA256SUMS` line.
fn panel(fetcher: &dyn Fetcher, current: Option<&str>) -> Result<Value, UpstreamError> {
    let releases = releases(fetcher, PANEL_REPOSITORY, true)?;
    let Some(first) = releases.first() else {
        return Ok(nothing("no_releases"));
    };
    let mut candidates = Vec::new();
    let mut reason: Option<&str> = None;
    for release in &releases {
        if current.is_some_and(|current| compare_versions(&release.version, current) <= 0) {
            continue;
        }
        let name = format!("proxy-control-v{}.tar.gz", release.version);
        let url = asset_url(&release.assets, &name, PANEL_REPOSITORY)?;
        let sums_url = asset_url(&release.assets, PANEL_SUMS_ASSET, PANEL_REPOSITORY)?;
        let (Some(url), Some(sums_url)) = (url, sums_url) else {
            reason = reason.or(Some("no_published_digest"));
            continue;
        };
        let answer = fetcher.fetch(&sums_url, &[], MAX_SUMS_FILE)?;
        if answer.status != 200 {
            reason = reason.or(Some("no_published_digest"));
            continue;
        }
        let Ok(digest) = parse_sha256sums(&String::from_utf8_lossy(&answer.body), &name) else {
            reason = reason.or(Some("no_published_digest"));
            continue;
        };
        candidates.push(json!({
            "version": release.version, "tag": release.tag, "kind": "release", "source": "upstream", "url": url,
            "sha256": digest, "published_at": release.published_at,
        }));
    }
    let installable = !candidates.is_empty();
    Ok(json!({"latest": first.version, "installable": installable, "reason": if installable { None } else { reason },
              "candidates": candidates}))
}

/// `_amneziawg`: amneziawg-go's tags `v<dotted digits>` with their commits; the installed tag
/// stays among the candidates.
fn amneziawg(fetcher: &dyn Fetcher, current: Option<&str>) -> Result<Value, UpstreamError> {
    let items = json_of(
        fetcher,
        &format!("https://api.github.com/repos/{AMNEZIAWG_REPOSITORY}/tags?per_page=30"),
        MAX_JSON,
        &[],
    )?;
    let Value::Array(items) = items else {
        return fail("tags answer is not a list");
    };
    let mut tags: Vec<(String, String, String)> = Vec::new();
    for item in &items {
        let Some(item) = item.as_object() else { continue };
        let Some(commit) = item.get("commit").and_then(Value::as_object) else { continue };
        let (Some(name), Some(sha)) =
            (item.get("name").and_then(Value::as_str), commit.get("sha").and_then(Value::as_str))
        else {
            continue;
        };
        let Some(version) = name.strip_prefix('v') else { continue };
        if is_dotted(version) && is_hex40(sha) {
            tags.push((version.to_string(), name.to_string(), sha.to_string()));
        }
    }
    let Some(_) = tags.first() else {
        return Ok(nothing("no_releases"));
    };
    sort_by_parts_desc(&mut tags, |tag| &tag.0);
    let latest = tags[0].0.clone();
    let candidates = tags
        .into_iter()
        .take(MAX_CANDIDATES + 1)
        .map(|(version, name, commit)| {
            json!({"version": version, "tag": name, "kind": "build", "source": "upstream",
                   "build": {"commit": commit, "tag": name}, "published_at": null})
        })
        .collect();
    Ok(probe(Value::String(latest), current, candidates, None))
}

/// `_trusttunnel`: stable releases whose x86_64 archive carries GitHub's SHA-256.
fn trusttunnel(fetcher: &dyn Fetcher, current: Option<&str>) -> Result<Value, UpstreamError> {
    let items = json_of(
        fetcher,
        &format!("https://api.github.com/repos/{TRUSTTUNNEL_REPOSITORY}/releases?per_page=10"),
        MAX_JSON,
        &[],
    )?;
    let Value::Array(items) = items else {
        return fail("releases answer is not a list");
    };
    let mut releases: Vec<Value> = Vec::new();
    let mut reason: Option<&str> = None;
    for item in &items {
        let Some(item) = item.as_object() else { continue };
        if get_truthy(item, "draft") || get_truthy(item, "prerelease") {
            continue;
        }
        let Some(tag) = item.get("tag_name").and_then(Value::as_str) else { continue };
        let Some(version) = tag.strip_prefix('v').filter(|v| is_dotted(v)) else { continue };
        let name = format!("trusttunnel-{tag}-linux-x86_64.tar.gz");
        let asset = list_of(item.get("assets"))
            .iter()
            .filter_map(Value::as_object)
            .find(|a| a.get("name").and_then(Value::as_str) == Some(name.as_str()));
        let digest = asset.and_then(|a| a.get("digest")).and_then(Value::as_str).filter(|d| is_digest(d));
        let size = asset.and_then(|a| a.get("size")).and_then(crate::py::as_strict_int);
        let (Some(asset), Some(digest), Some(_)) =
            (asset, digest, size.filter(|s| (1..=MAX_TRUSTTUNNEL_ARCHIVE).contains(s)))
        else {
            if current.is_none_or(|current| compare_versions(version, current) > 0) {
                reason = reason.or(Some("no_published_digest"));
            }
            continue;
        };
        let mut single = BTreeMap::new();
        single.insert(name.clone(), asset.get("browser_download_url").cloned().unwrap_or(Value::Null));
        let url = asset_url(&single, &name, TRUSTTUNNEL_REPOSITORY)?;
        let expected = format!("https://github.com/{TRUSTTUNNEL_REPOSITORY}/releases/download/{tag}/{name}");
        if url.as_deref() != Some(expected.as_str()) {
            return fail("asset URL is not the release download of its repository");
        }
        releases.push(json!({"version": version, "tag": tag, "kind": "build", "source": "upstream", "url": expected,
                             "sha256": &digest[7..], "published_at": published(item)}));
    }
    if releases.is_empty() {
        return Ok(nothing(reason.unwrap_or("no_releases")));
    }
    sort_by_parts_desc(&mut releases, |r| candidate_version(r));
    let latest = Value::String(candidate_version(&releases[0]).to_string());
    releases.truncate(MAX_CANDIDATES + 1);
    Ok(probe(latest, current, releases, reason))
}

/// `check_component`.
pub fn check_component(
    component: &str,
    current: Option<&str>,
    fetcher: &dyn Fetcher,
    router_enabled: bool,
) -> Result<Value, UpstreamError> {
    match component {
        "panel" => panel(fetcher, current),
        "xray" if !router_enabled => Ok(nothing("router_not_installed")),
        "xray" => github_binary(
            fetcher,
            current,
            &BinarySource {
                repository: "XTLS/Xray-core",
                asset: &|_: &str| String::from("Xray-linux-64.zip"),
                digest_suffix: ".dgst",
                parse: parse_dgst,
                archive: json!({"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}),
                // XTLS marks every Xray-core release a pre-release.
                prereleases: true,
            },
        ),
        "mita" => github_binary(
            fetcher,
            current,
            &BinarySource {
                repository: "enfein/mieru",
                asset: &|version: &str| format!("mita_{version}_linux_amd64.tar.gz"),
                digest_suffix: ".sha256.txt",
                parse: parse_sha256_txt,
                archive: json!({"format": "tar.gz", "member": "mita"}),
                prereleases: false,
            },
        ),
        "telemt" => telemt(fetcher, current),
        "naive" => naive(fetcher, current),
        "amneziawg" => amneziawg(fetcher, current),
        "trusttunnel" => trusttunnel(fetcher, current),
        _ => fail("unknown component"),
    }
}

/// `check_all`: every component the host runs, sequentially; a failed source becomes
/// `last_error` and the next one is still probed.
pub fn check_all(
    current: &BTreeMap<String, Option<String>>,
    fetcher: &dyn Fetcher,
    router_enabled: bool,
) -> Map<String, Value> {
    let mut result = Map::new();
    for component in COMPONENTS {
        // The protocol managers are probed only on a host that runs them.
        if OPTIONAL_COMPONENTS.contains(&component) && !current.contains_key(component) {
            continue;
        }
        let installed = current.get(component).cloned().flatten();
        let probed = check_component(component, installed.as_deref(), fetcher, router_enabled).unwrap_or_else(
            |err| json!({"latest": null, "installable": false, "reason": null, "candidates": [], "last_error": err.0}),
        );
        result.insert(component.to_string(), probed);
    }
    result
}

#[cfg(test)]
mod tests;
