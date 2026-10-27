//! Geodata of the router (v0.8): where `geosite.dat` / `geoip.dat` come from and how they change.
//!
//! The files Xray resolves `geosite:` / `geoip:` codes against live in the manager's own state
//! directory (`<state>/geodata`), never in the read-only binary directory: the installer's pinned
//! pair is the **seed** the manager copies there on first start, and everything after that is the
//! operator's choice — the seed again, a maintained regional list, or any two HTTPS URLs.
//!
//! An update is a transaction: both files are downloaded to a temporary name (size-capped, HTTPS
//! only, the `<url>.sha256sum` sidecar honoured when the publisher offers one), the running
//! generation's config is `xray run -test`-ed against the candidates, then the files are swapped
//! atomically and the router restarts on them. A failure leaves the previous files in place and is
//! recorded as `last_error`.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::errors::{Error, Result};
use crate::https;
use crate::pyjson;
use crate::util::{iso_utc, py_decimal, sha256_hex};
use pc_common::pytext::{head_chars as first_chars, is_space as py_isspace, strip as py_strip};
use pc_common::pyvalue::{strict_int as json_int, truthy as py_truthy};

pub const FILES: [&str; 2] = ["geosite", "geoip"];
pub const SOURCE_KINDS: [&str; 6] = ["xray", "loyalsoldier", "runetfreedom", "iran", "v2fly", "custom"];
pub const DEFAULT_SOURCE: &str = "loyalsoldier";
/// runetfreedom's geosite.dat alone is ~74 MB.
pub const MAX_FILE_BYTES: usize = 128 * 1024 * 1024;
pub const MIN_INTERVAL_HOURS: i64 = 1;
pub const MAX_INTERVAL_HOURS: i64 = 24 * 14;
pub const DEFAULT_INTERVAL_HOURS: i64 = 24;
/// A daily (or longer) update restarts Xray and drops the router's connections: it waits for this
/// UTC hour — 02:00 UTC is the night in Europe and Russia.
pub const DEFAULT_UPDATE_HOUR: i64 = 2;
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
pub const USER_AGENT: &str = "proxy-control-xray-router/0.8";

/// The geosite and geoip URLs of a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Urls {
    pub geosite: String,
    pub geoip: String,
}

impl Urls {
    pub fn get(&self, name: &str) -> &str {
        if name == "geosite" {
            &self.geosite
        } else {
            &self.geoip
        }
    }
}

fn release(repository: &str) -> Urls {
    let base = format!("https://github.com/{repository}/releases/latest/download");
    Urls { geosite: format!("{base}/geosite.dat"), geoip: format!("{base}/geoip.dat") }
}

/// v1.0.1: the maintained regional lists as ready sources — every publisher ships
/// `<file>.sha256sum` beside the files, which the download checks.
pub fn preset_urls(kind: &str) -> Option<Urls> {
    match kind {
        // China plus the general categories (ads, gfw, geolocation-!cn); the default.
        "loyalsoldier" => Some(release("Loyalsoldier/v2ray-rules-dat")),
        // Russia: ru-blocked / ru-available-only-inside on top of the general categories.
        "runetfreedom" => Some(release("runetfreedom/russia-v2ray-rules-dat")),
        // Iran: category-ir and its sub-categories, geoip:ir.
        "iran" => Some(release("chocolate4u/Iran-v2ray-rules")),
        // The upstream community lists, no regional additions.
        "v2fly" => Some(Urls {
            geosite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat".into(),
            geoip: "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat".into(),
        }),
        _ => None,
    }
}

#[cfg(test)]
pub const PRESETS: [&str; 4] = ["loyalsoldier", "runetfreedom", "iran", "v2fly"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub kind: String,
    pub geosite_url: Option<String>,
    pub geoip_url: Option<String>,
}

impl Source {
    pub fn of(kind: &str) -> Self {
        Self { kind: kind.into(), geosite_url: None, geoip_url: None }
    }

    pub fn urls(&self) -> Option<Urls> {
        if let Some(urls) = preset_urls(&self.kind) {
            return Some(urls);
        }
        (self.kind == "custom").then(|| Urls {
            geosite: self.geosite_url.clone().unwrap_or_default(),
            geoip: self.geoip_url.clone().unwrap_or_default(),
        })
    }

    pub fn wire(&self) -> Value {
        json!({"kind": self.kind, "geosite_url": self.geosite_url, "geoip_url": self.geoip_url})
    }
}

/// `^https://[A-Za-z0-9.-]+(?::\d{1,5})?/[^\s]{1,1024}$`
pub fn is_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host_end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).unwrap_or(rest.len());
    if host_end == 0 {
        return false;
    }
    let mut rest = &rest[host_end..];
    if let Some(after) = rest.strip_prefix(':') {
        let digits = after.chars().take_while(|c| py_decimal(*c).is_some()).count();
        if !(1..=5).contains(&digits) {
            return false;
        }
        let end = after.char_indices().nth(digits).map_or(after.len(), |(i, _)| i);
        rest = &after[end..];
    }
    let Some(path) = rest.strip_prefix('/') else { return false };
    (1..=1024).contains(&path.chars().count()) && !path.chars().any(py_isspace)
}

/// `{"kind": ..., "geosite_url"?, "geoip_url"?}` validated: custom needs two HTTPS URLs.
pub fn parse_source(value: &Value) -> Result<Source> {
    let kind = value.get("kind").and_then(Value::as_str).filter(|kind| SOURCE_KINDS.contains(kind));
    let Some(kind) = kind.filter(|_| value.is_object()) else {
        return Err(Error::geodata(
            format!("source.kind must be one of {}", SOURCE_KINDS.join(", ")),
            "geodata_invalid",
        ));
    };
    if kind != "custom" {
        return Ok(Source::of(kind));
    }
    let mut urls = Vec::new();
    for name in FILES {
        match value.get(format!("{name}_url")).and_then(Value::as_str).map(py_strip) {
            Some(url) if is_https_url(url) => urls.push(url.to_string()),
            _ => return Err(Error::geodata(format!("{name}_url must be an https URL"), "geodata_invalid")),
        }
    }
    Ok(Source { kind: "custom".into(), geosite_url: Some(urls[0].clone()), geoip_url: Some(urls[1].clone()) })
}

pub fn parse_hour(value: &Value) -> Result<Value> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    match json_int(value) {
        Some(hour) if (0..=23).contains(&hour) => Ok(value.clone()),
        _ => Err(Error::geodata("update_hour must be 0..23 (UTC) or null", "geodata_invalid")),
    }
}

pub fn parse_interval(value: &Value) -> Result<Value> {
    match json_int(value) {
        Some(hours) if (MIN_INTERVAL_HOURS as i128..=MAX_INTERVAL_HOURS as i128).contains(&hours) => Ok(value.clone()),
        _ => Err(Error::geodata(
            format!("interval_hours must be {MIN_INTERVAL_HOURS}..{MAX_INTERVAL_HOURS}"),
            "geodata_invalid",
        )),
    }
}

// ----------------------------------------------------------------- the .dat format

fn corrupt(message: &str) -> Error {
    Error::geodata(message, "geodata_corrupt")
}

fn varint(data: &[u8], mut pos: usize) -> Result<(u128, usize)> {
    let (mut result, mut shift) = (0u128, 0u32);
    loop {
        let Some(&byte) = data.get(pos) else { return Err(corrupt("truncated geodata file")) };
        pos += 1;
        result |= u128::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos));
        }
        shift += 7;
        if shift > 63 {
            return Err(corrupt("malformed geodata file"));
        }
    }
}

fn advance(pos: usize, by: u128) -> usize {
    usize::try_from(by).ok().and_then(|by| pos.checked_add(by)).unwrap_or(usize::MAX)
}

fn skip(data: &[u8], pos: usize, wire_type: u128) -> Result<usize> {
    match wire_type {
        0 => Ok(varint(data, pos)?.1),
        1 => Ok(advance(pos, 8)),
        2 => {
            let (length, pos) = varint(data, pos)?;
            Ok(advance(pos, length))
        }
        5 => Ok(advance(pos, 4)),
        _ => Err(corrupt("malformed geodata file")),
    }
}

/// The `country_code` of every entry of a `GeoSiteList` / `GeoIPList` (both are
/// `repeated Entry entry = 1` with `string country_code = 1`), lower-cased and sorted — without
/// decoding the domains or CIDRs themselves.
pub fn parse_codes(data: &[u8]) -> Result<Vec<String>> {
    let mut codes = std::collections::BTreeSet::new();
    let mut pos = 0;
    while pos < data.len() {
        let (key, next) = varint(data, pos)?;
        pos = next;
        if key >> 3 != 1 || key & 7 != 2 {
            pos = skip(data, pos, key & 7)?;
            continue;
        }
        let (length, next) = varint(data, pos)?;
        let end = advance(next, length);
        let entry = &data[next.min(data.len())..end.min(data.len())];
        pos = end;
        let mut inner = 0;
        while inner < entry.len() {
            let (ikey, next) = varint(entry, inner)?;
            inner = next;
            if ikey >> 3 == 1 && ikey & 7 == 2 {
                let (size, next) = varint(entry, inner)?;
                let end = advance(next, size);
                let code = &entry[next.min(entry.len())..end.min(entry.len())];
                codes.insert(String::from_utf8_lossy(code).to_lowercase());
                inner = end;
            } else {
                inner = skip(entry, inner, ikey & 7)?;
            }
        }
    }
    if codes.is_empty() {
        return Err(corrupt("no entries in geodata file"));
    }
    Ok(codes.into_iter().collect())
}

// ------------------------------------------------------------------- downloads

/// `(url, max_bytes) -> (body, the URL that names the release)`.
pub type Fetcher = dyn Fn(&str, usize) -> Result<(Vec<u8>, String)> + Send + Sync;

/// `/releases/download/([^/]+)/`: the release tag a URL names.
pub fn release_tag(url: &str) -> Option<&str> {
    const MARK: &str = "/releases/download/";
    let mut from = 0;
    while let Some(found) = url[from..].find(MARK) {
        let start = from + found + MARK.len();
        if let Some(length) = url[start..].find('/') {
            if length > 0 {
                return Some(&url[start..start + length]);
            }
        }
        from = from + found + 1;
    }
    None
}

/// The body of an HTTPS URL (redirects allowed, HTTPS end to end) and the URL to report.
pub fn fetch(url: &str, max_bytes: usize) -> Result<(Vec<u8>, String)> {
    fetch_with(url, max_bytes, DOWNLOAD_TIMEOUT)
}

pub fn fetch_with(url: &str, max_bytes: usize, timeout: Duration) -> Result<(Vec<u8>, String)> {
    let headers = [("User-Agent", USER_AGENT), ("Accept", "*/*")];
    fetch_via(url, max_bytes, &|parsed: &https::Url| {
        https::request(parsed, "GET", &headers, None, timeout, max_bytes.saturating_add(1))
    })
}

/// One GET of `url`, its redirects followed through `send` (urllib's rules: 301/302/303/307/308,
/// at most 10 distinct targets, 4 visits each).
pub fn fetch_via(
    url: &str,
    max_bytes: usize,
    send: &dyn Fn(&https::Url) -> std::result::Result<https::Response, https::Failure>,
) -> Result<(Vec<u8>, String)> {
    if !is_https_url(url) {
        return Err(Error::geodata("only https URLs are fetched", "geodata_invalid"));
    }
    let failed =
        |text: String| Error::geodata(first_chars(&format!("fetch failed: {text}"), 300), "geodata_fetch_failed");
    let mut current = url.to_string();
    let mut hops: Vec<String> = Vec::new();
    let mut visited: HashMap<String, usize> = HashMap::new();
    let data = loop {
        let parsed =
            https::parse_url(&current).ok_or_else(|| failed(format!("<urlopen error unknown url type: {current}>")))?;
        let response = match send(&parsed) {
            Ok(response) => response,
            Err(https::Failure::Open(reason)) => return Err(failed(format!("<urlopen error {reason}>"))),
            Err(https::Failure::Read(text)) => return Err(failed(text)),
        };
        let (status, reason) = (response.status, response.reason.clone());
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let Some(location) = response.header("location").or_else(|| response.header("uri")) else {
                return Err(failed(format!("HTTP Error {status}: {reason}")));
            };
            let next = https::join(&parsed, location);
            hops.push(next.clone());
            if !next.starts_with("https://") {
                return Err(Error::geodata("redirected off https", "geodata_fetch_failed"));
            }
            if visited.len() >= 10 || visited.get(&next).copied().unwrap_or(0) >= 4 {
                return Err(failed(format!(
                    "HTTP Error {status}: The HTTP server returned a redirect error that would lead to an infinite loop.\n\
                     The last 30x error message was:\n{reason}"
                )));
            }
            *visited.entry(next.clone()).or_default() += 1;
            current = next;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(failed(format!("HTTP Error {status}: {reason}")));
        }
        break response.body;
    };
    if data.len() > max_bytes {
        return Err(Error::geodata("file larger than the limit", "geodata_too_large"));
    }
    if data.is_empty() {
        return Err(Error::geodata("empty file", "geodata_fetch_failed"));
    }
    // GitHub's `releases/latest/download/…` names the release only on its first hop; the last hop
    // is a signed asset URL without it — report the hop that carries the release tag.
    let reported = hops.iter().find(|hop| release_tag(hop).is_some()).cloned().unwrap_or(current);
    Ok((data, reported))
}

/// One file of a downloaded pair.
#[derive(Debug, Clone)]
#[allow(dead_code)] // the facts the Python store kept with a download; only some are read
pub struct Downloaded {
    pub data: Vec<u8>,
    pub sha256: String,
    pub verified: bool,
    pub codes: Vec<String>,
    pub version: Option<String>,
    pub url: String,
}

/// `<url>.sha256sum`'s digest: the first `\b[0-9a-fA-F]{64}\b`.
fn published_digest(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let word = |c: char| c.is_alphanumeric() || c == '_';
    for start in 0..chars.len() {
        if start > 0 && word(chars[start - 1]) {
            continue;
        }
        if start + 64 > chars.len() || !chars[start..start + 64].iter().all(char::is_ascii_hexdigit) {
            continue;
        }
        if start + 64 < chars.len() && word(chars[start + 64]) {
            continue;
        }
        return Some(chars[start..start + 64].iter().collect::<String>().to_lowercase());
    }
    None
}

/// Both files of a source: bytes, sha256, and — when `<url>.sha256sum` answers — the publisher's
/// digest checked against ours. A sidecar that does not answer is not an error (a custom mirror may
/// not publish one); a sidecar that disagrees is.
pub fn download_pair(urls: &Urls, fetcher: &Fetcher) -> Result<Vec<(String, Downloaded)>> {
    let mut result = Vec::new();
    for name in FILES {
        let url = urls.get(name);
        let (data, reported) = fetcher(url, MAX_FILE_BYTES)?;
        let digest = sha256_hex(&data);
        let published = match fetcher(&format!("{url}.sha256sum"), 4096) {
            Ok((sidecar, _)) => published_digest(&String::from_utf8_lossy(&sidecar)),
            Err(Error::Geodata { .. }) => None,
            Err(other) => return Err(other),
        };
        if published.as_ref().is_some_and(|published| published != &digest) {
            return Err(Error::geodata(
                format!("{name}.dat does not match its published sha256"),
                "geodata_digest_mismatch",
            ));
        }
        let codes =
            parse_codes(&data).map_err(|err| Error::geodata(format!("{name}.dat: {err}"), err.code().unwrap_or("")))?;
        let version = release_tag(&reported).map(str::to_string);
        result.push((
            name.to_string(),
            Downloaded { data, sha256: digest, verified: published.is_some(), codes, version, url: reported },
        ));
    }
    Ok(result)
}

// ---------------------------------------------------------------------- store

/// A downloaded (or copied) file waiting under a temporary name beside its final one.
#[derive(Debug, Clone)]
pub struct Staged {
    pub tmp: PathBuf,
    pub version: Option<String>,
}

pub type StagedPair = Vec<(String, Staged)>;
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// `<state>/geodata`: the two files Xray reads, `meta.json` beside them, the seed to fall back to.
/// Swaps are atomic renames within the directory; the caller restarts Xray.
pub struct GeodataStore {
    pub directory: PathBuf,
    /// geosite, geoip — the pinned pair in the binary directory.
    pub seed: Vec<(String, PathBuf)>,
    clock: RwLock<Clock>,
    codes_cache: Mutex<HashMap<String, (String, Vec<String>)>>,
}

fn sha256_path(path: &Path) -> Option<String> {
    fs::read(path).ok().map(|data| sha256_hex(&data))
}

fn as_float(value: Option<&Value>) -> f64 {
    value.and_then(Value::as_f64).unwrap_or(0.0)
}

impl GeodataStore {
    pub fn new(directory: PathBuf, seed: Vec<(String, PathBuf)>) -> Self {
        Self {
            directory,
            seed,
            clock: RwLock::new(Arc::new(crate::util::unix_now)),
            codes_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_clock(&self, clock: Clock) {
        *self.clock.write().unwrap_or_else(PoisonError::into_inner) = clock;
    }

    pub fn now(&self) -> f64 {
        let clock = self.clock.read().unwrap_or_else(PoisonError::into_inner).clone();
        clock()
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{name}.dat"))
    }

    fn seed_path(&self, name: &str) -> Result<&Path> {
        self.seed
            .iter()
            .find(|(seed, _)| seed == name)
            .map(|(_, path)| path.as_path())
            .ok_or_else(|| Error::Internal(format!("'{name}'")))
    }

    fn default_meta() -> Map<String, Value> {
        let default = json!({"source": Source::of(DEFAULT_SOURCE).wire(), "auto_update": true,
                             "interval_hours": DEFAULT_INTERVAL_HOURS, "update_hour": DEFAULT_UPDATE_HOUR, "origin": "seed",
                             "version": null, "updated_at": null, "last_check_at": null, "last_error": null, "files": {},
                             "schema": 2});
        default.as_object().expect("an object").clone()
    }

    pub fn meta(&self) -> Map<String, Value> {
        let mut meta = Self::default_meta();
        let Ok(text) = fs::read(self.directory.join("meta.json")) else { return meta };
        let Ok(Value::Object(mut value)) = serde_json::from_slice::<Value>(&text) else { return meta };
        if !value.contains_key("schema") {
            // Before v1.0.1 a router started on the pin with no updates. A pin nobody chose (never
            // checked: «Вернуть пин» leaves a check time) takes the new default.
            let untouched = value.get("source").and_then(|s| s.get("kind")).and_then(Value::as_str) == Some("xray")
                && !value.get("auto_update").is_some_and(py_truthy)
                && value.get("last_check_at").is_none_or(Value::is_null);
            let hour = value.get("update_hour").cloned().unwrap_or(json!(DEFAULT_UPDATE_HOUR));
            value.insert("schema".into(), json!(2));
            value.insert("update_hour".into(), hour);
            if untouched {
                value.insert("source".into(), Source::of(DEFAULT_SOURCE).wire());
                value.insert("auto_update".into(), json!(true));
            }
        }
        for (key, item) in value {
            meta.insert(key, item);
        }
        meta
    }

    pub fn write_meta(&self, meta: &Map<String, Value>) -> Result<()> {
        fs::create_dir_all(&self.directory)?;
        let mut data = pc_common::json::dumps(&Value::Object(meta.clone()), &pyjson::SORTED).into_bytes();
        data.push(b'\n');
        crate::util::atomic_write_geodata(&self.directory.join("meta.json"), &data, 0o600)?;
        Ok(())
    }

    fn file_facts(&self) -> Map<String, Value> {
        let mut facts = Map::new();
        for name in FILES {
            let fact = match fs::read(self.path(name)) {
                Ok(data) => {
                    let digest = sha256_hex(&data);
                    let codes = self.codes_for(name, &digest, &data).len();
                    json!({"sha256": digest, "size": data.len(), "codes": codes})
                }
                Err(_) => json!({"sha256": null, "size": 0, "codes": 0}),
            };
            facts.insert(name.into(), fact);
        }
        facts
    }

    fn codes_for(&self, name: &str, digest: &str, data: &[u8]) -> Vec<String> {
        let mut cache = self.codes_cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached_digest, codes)) = cache.get(name) {
            if cached_digest == digest {
                return codes.clone();
            }
        }
        let codes = parse_codes(data).unwrap_or_default();
        cache.insert(name.to_string(), (digest.to_string(), codes.clone()));
        codes
    }

    /// Copy the pinned pair in when the directory has no files yet. True when it did.
    pub fn ensure_seed(&self) -> Result<bool> {
        if FILES.iter().all(|name| self.path(name).exists()) {
            return Ok(false);
        }
        fs::create_dir_all(&self.directory)?;
        for name in FILES {
            crate::util::atomic_write_geodata(&self.path(name), &fs::read(self.seed_path(name)?)?, 0o644)?;
        }
        let mut meta = self.meta();
        meta.insert("origin".into(), json!("seed"));
        meta.insert("version".into(), Value::Null);
        meta.insert("updated_at".into(), json!(iso_utc(self.now())));
        meta.insert("last_error".into(), Value::Null);
        meta.insert("files".into(), Value::Object(self.file_facts()));
        self.write_meta(&meta)?;
        Ok(true)
    }

    pub fn view(&self) -> Value {
        let mut view = self.meta();
        let next = self.next_check(&view);
        view.insert("next_check_at".into(), next.map_or(Value::Null, Value::from));
        view.insert("files".into(), Value::Object(self.file_facts()));
        let seed: Map<String, Value> =
            self.seed.iter().map(|(name, path)| (name.clone(), json!({"sha256": sha256_path(path)}))).collect();
        view.insert("seed".into(), Value::Object(seed));
        view.insert(
            "limits".into(),
            json!({"max_file_bytes": MAX_FILE_BYTES, "interval_hours": [MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS]}),
        );
        Value::Object(view)
    }

    pub fn codes(&self) -> Value {
        let mut result = Map::new();
        for name in FILES {
            let codes = match fs::read(self.path(name)) {
                Ok(data) => self.codes_for(name, &sha256_hex(&data), &data),
                Err(_) => Vec::new(),
            };
            result.insert(name.into(), json!(codes));
        }
        Value::Object(result)
    }

    /// `update_hour`: `None` leaves it, `Some(value)` sets it (`null` = any hour).
    pub fn settings(
        &self,
        source: Option<&Source>,
        auto_update: Option<bool>,
        interval_hours: Option<&Value>,
        update_hour: Option<&Value>,
    ) -> Result<Value> {
        let mut meta = self.meta();
        if let Some(hour) = update_hour {
            meta.insert("update_hour".into(), parse_hour(hour)?);
        }
        if let Some(source) = source {
            meta.insert("source".into(), source.wire());
        }
        if let Some(auto) = auto_update {
            meta.insert("auto_update".into(), json!(auto));
        }
        if let Some(interval) = interval_hours.filter(|value| !value.is_null()) {
            meta.insert("interval_hours".into(), parse_interval(interval)?);
        }
        self.write_meta(&meta)?;
        Ok(self.view())
    }

    /// When the next automatic check may run: the interval after the last one — for a daily or
    /// longer interval, inside the next `update_hour` window from then (an hour's slack). A window
    /// that passed unused (the host was down) moves to the next day's.
    pub fn next_check(&self, meta: &Map<String, Value>) -> Option<f64> {
        let source_kind = meta.get("source").and_then(|s| s.get("kind")).and_then(Value::as_str);
        if !meta.get("auto_update").is_some_and(py_truthy) || source_kind == Some("xray") {
            return None;
        }
        let last = meta.get("last_check_at");
        let now = self.now();
        if !last.is_some_and(py_truthy) {
            return Some(now);
        }
        let hours = meta
            .get("interval_hours")
            .filter(|v| py_truthy(v))
            .and_then(Value::as_f64)
            .unwrap_or(DEFAULT_INTERVAL_HOURS as f64);
        let interval = hours.trunc() * 3600.0;
        let last = as_float(last);
        let Some(hour) = meta.get("update_hour").filter(|v| !v.is_null()).and_then(Value::as_f64) else {
            return Some(last + interval);
        };
        if interval < 86400.0 {
            return Some(last + interval);
        }
        let earliest = last + interval - 3600.0;
        let window = |moment: f64| {
            let start = moment - moment.rem_euclid(86400.0) + hour * 3600.0;
            if start + 3600.0 > moment {
                start
            } else {
                start + 86400.0
            }
        };
        let mut start = window(earliest);
        if now >= start + 3600.0 {
            start = window(now);
        }
        Some(start.max(earliest))
    }

    pub fn due(&self) -> bool {
        self.next_check(&self.meta()).is_some_and(|next| self.now() >= next)
    }

    /// With the pin as the source the live pair is the seed: after the version-agent installed a
    /// new Xray release (a new seed), copy it in. True when it did.
    pub fn follow_seed(&self) -> Result<bool> {
        let mut meta = self.meta();
        let kind = meta.get("source").and_then(|s| s.get("kind")).and_then(Value::as_str);
        if kind != Some("xray") || meta.get("origin").and_then(Value::as_str) != Some("seed") {
            return Ok(false);
        }
        let mut same = true;
        for name in FILES {
            if sha256_path(self.seed_path(name)?) != sha256_path(&self.path(name)) {
                same = false;
            }
        }
        if same {
            return Ok(false);
        }
        for name in FILES {
            crate::util::atomic_write_geodata(&self.path(name), &fs::read(self.seed_path(name)?)?, 0o644)?;
        }
        meta.insert("updated_at".into(), json!(iso_utc(self.now())));
        meta.insert("last_error".into(), Value::Null);
        meta.insert("files".into(), Value::Object(self.file_facts()));
        self.write_meta(&meta)?;
        Ok(true)
    }

    /// Download the source's pair into the directory under temporary names. `None` when the source
    /// is the seed (nothing to fetch) or the files already are what the source serves.
    pub fn stage(&self, fetcher: &Fetcher) -> Result<Option<StagedPair>> {
        let mut meta = self.meta();
        let source = parse_source(meta.get("source").unwrap_or(&Value::Null))?;
        let Some(urls) = source.urls() else { return Ok(None) };
        let downloaded = download_pair(&urls, fetcher)?;
        let current = self.file_facts();
        let unchanged = downloaded
            .iter()
            .all(|(name, file)| current[name.as_str()]["sha256"].as_str() == Some(file.sha256.as_str()));
        if unchanged {
            meta.insert("last_check_at".into(), Value::from(self.now()));
            meta.insert("last_error".into(), Value::Null);
            self.write_meta(&meta)?;
            return Ok(None);
        }
        fs::create_dir_all(&self.directory)?;
        let mut staged = Vec::new();
        for (name, file) in downloaded {
            let (mut handle, tmp) = crate::util::mkstemp(&self.directory, &format!("{name}."), ".dat.tmp")?;
            handle.write_all(&file.data)?;
            handle.flush()?;
            handle.sync_all()?;
            drop(handle);
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
            staged.push((name, Staged { tmp, version: file.version }));
        }
        Ok(Some(staged))
    }

    pub fn discard(&self, staged: &StagedPair) {
        for (_, entry) in staged {
            let _ = crate::util::unlink_missing_ok(&entry.tmp);
        }
    }

    pub fn commit(&self, staged: &StagedPair, origin: &str) -> Result<Value> {
        for name in FILES {
            let entry =
                staged.iter().find(|(staged, _)| staged == name).ok_or_else(|| Error::Internal(format!("'{name}'")))?;
            fs::rename(&entry.1.tmp, self.path(name))?;
        }
        let _ = crate::util::fsync_directory(&self.directory);
        let mut meta = self.meta();
        let mut versions: Vec<String> =
            staged.iter().filter_map(|(_, entry)| entry.version.clone()).filter(|v| !v.is_empty()).collect();
        versions.sort();
        meta.insert("origin".into(), json!(origin));
        meta.insert("version".into(), versions.first().map_or(Value::Null, |v| json!(v)));
        meta.insert("updated_at".into(), json!(iso_utc(self.now())));
        meta.insert("last_check_at".into(), Value::from(self.now()));
        meta.insert("last_error".into(), Value::Null);
        meta.insert("files".into(), Value::Object(self.file_facts()));
        self.write_meta(&meta)?;
        Ok(self.view())
    }

    pub fn record_failure(&self, error: &Error) -> Result<()> {
        let mut meta = self.meta();
        meta.insert("last_check_at".into(), Value::from(self.now()));
        let text = format!("{}: {error}", error.code().unwrap_or(""));
        meta.insert("last_error".into(), json!(first_chars(&text, 300)));
        self.write_meta(&meta)
    }

    /// A directory Xray can be pointed at (`XRAY_LOCATION_ASSET`) to test the candidates: the
    /// staged files hard-linked under their final names.
    pub fn staged_dir(&self, staged: &StagedPair) -> Result<PathBuf> {
        let directory = crate::util::mkdtemp(&self.directory, "geodata-test.")?;
        for name in FILES {
            let entry =
                staged.iter().find(|(staged, _)| staged == name).ok_or_else(|| Error::Internal(format!("'{name}'")))?;
            fs::hard_link(&entry.1.tmp, directory.join(format!("{name}.dat")))?;
        }
        Ok(directory)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value > 0 {
                out.push(byte | 0x80);
            } else {
                out.push(byte);
                return out;
            }
        }
    }

    fn field(number: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = varint_bytes((number << 3) | 2);
        out.extend(varint_bytes(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// A `GeoSiteList` with one entry per code; entries carry a second field (a domain or a CIDR)
    /// and a varint the parser has to skip, exactly as real files do.
    pub fn geodata_file(codes: &[&str]) -> Vec<u8> {
        let mut entries = Vec::new();
        for code in codes {
            let mut entry = field(1, code.as_bytes());
            let mut inner = field(2, b"example.com");
            inner.extend(varint_bytes(1 << 3));
            inner.extend(varint_bytes(2));
            entry.extend(field(2, &inner));
            entry.extend(varint_bytes(3 << 3));
            entry.extend(varint_bytes(1));
            entries.extend(field(1, &entry));
        }
        entries
    }

    #[test]
    fn parse_codes_reads_country_codes_and_skips_the_rest() {
        assert_eq!(
            parse_codes(&geodata_file(&["CN", "category-ads-all", "ru"])).unwrap(),
            ["category-ads-all", "cn", "ru"]
        );
        assert!(parse_codes(b"").unwrap_err().to_string().contains("no entries"));
        assert!(parse_codes(b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff").is_err());
    }

    #[test]
    fn parse_source_and_interval_validate_the_operator_input() {
        assert_eq!(parse_source(&json!({"kind": "loyalsoldier"})).unwrap().urls(), preset_urls("loyalsoldier"));
        let custom = parse_source(&json!({"kind": "custom", "geosite_url": "https://mirror.example/geosite.dat ",
                                          "geoip_url": "https://mirror.example/geoip.dat"}))
        .unwrap();
        assert_eq!(
            custom.urls(),
            Some(Urls {
                geosite: "https://mirror.example/geosite.dat".into(),
                geoip: "https://mirror.example/geoip.dat".into()
            })
        );
        let http = parse_source(
            &json!({"kind": "custom", "geosite_url": "http://mirror.example/a", "geoip_url": "https://m/b"}),
        );
        assert!(http.unwrap_err().to_string().contains("https"));
        assert!(parse_source(&json!({"kind": "github"})).unwrap_err().to_string().contains("kind"));
        assert_eq!(Source::of("xray").urls(), None);
        assert!(is_https_url("https://m.example:\u{0661}\u{0662}/a") && !is_https_url("https://m.example:123456/a"));
        assert!(
            !is_https_url("https://m.example/a b")
                && !is_https_url("https://m_x/a")
                && !is_https_url("https://m.example/")
        );
    }

    #[test]
    fn regional_presets_are_sources_with_their_publishers_urls() {
        let mut kinds = SOURCE_KINDS.to_vec();
        kinds.sort();
        assert_eq!(kinds, ["custom", "iran", "loyalsoldier", "runetfreedom", "v2fly", "xray"]);
        for kind in PRESETS {
            let urls = preset_urls(kind).unwrap();
            assert_eq!(parse_source(&json!({"kind": kind})).unwrap().urls(), Some(urls.clone()));
            for url in [&urls.geosite, &urls.geoip] {
                assert!(url.starts_with("https://github.com/") && url.contains("/releases/latest/download/"));
            }
        }
        assert!(preset_urls("runetfreedom").unwrap().geosite.contains("runetfreedom/russia-v2ray-rules-dat"));
        const { assert!(MAX_FILE_BYTES >= 128 * 1024 * 1024) };
    }

    #[test]
    fn release_tags_and_published_digests() {
        let hop = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202609172350/geosite.dat";
        assert_eq!(release_tag(hop), Some("202609172350"));
        assert_eq!(release_tag("https://x/releases/download//releases/download/v1/a"), Some("v1"));
        assert_eq!(release_tag("https://release-assets.githubusercontent.com/asset/abc?sig=xyz"), None);
        let digest = "a".repeat(64);
        assert_eq!(published_digest(&format!("{}  geosite.dat\n", digest.to_uppercase())), Some(digest.clone()));
        assert_eq!(published_digest(&format!("x{digest}")), None);
        assert_eq!(published_digest(&format!("{digest}a")), None);
    }

    pub struct Publisher {
        pub files: HashMap<String, Vec<u8>>,
        pub sidecars: bool,
        pub lying: bool,
        pub reported: HashMap<String, String>,
        pub asked: Mutex<Vec<String>>,
    }

    impl Publisher {
        pub fn new(files: &[(&str, &[u8])]) -> Self {
            Self {
                files: files.iter().map(|(url, data)| (url.to_string(), data.to_vec())).collect(),
                sidecars: true,
                lying: false,
                reported: HashMap::new(),
                asked: Mutex::new(Vec::new()),
            }
        }

        pub fn fetch(&self, url: &str, max_bytes: usize) -> Result<(Vec<u8>, String)> {
            self.asked.lock().unwrap().push(url.to_string());
            if let Some(base) = url.strip_suffix(".sha256sum") {
                if self.lying {
                    return Ok((format!("{}  file\n", "0".repeat(64)).into_bytes(), url.into()));
                }
                return match self.files.get(base).filter(|_| self.sidecars) {
                    Some(data) => Ok((format!("{}  file\n", sha256_hex(data)).into_bytes(), url.into())),
                    None => Err(Error::geodata("404", "geodata_fetch_failed")),
                };
            }
            let data = self.files.get(url).ok_or_else(|| Error::geodata("404", "geodata_fetch_failed"))?;
            if data.len() > max_bytes {
                return Err(Error::geodata("file larger than the limit", "geodata_too_large"));
            }
            Ok((data.clone(), self.reported.get(url).cloned().unwrap_or_else(|| url.to_string())))
        }
    }

    #[test]
    fn download_pair_checks_the_published_digest_and_reads_the_release_tag() {
        let (site, ip) = (geodata_file(&["cn"]), geodata_file(&["ru"]));
        let urls = preset_urls("loyalsoldier").unwrap();
        let mut publisher = Publisher::new(&[(&urls.geosite, &site), (&urls.geoip, &ip)]);
        publisher.reported.insert(
            urls.geosite.clone(),
            "https://objects.githubusercontent.com/releases/download/202609172350/geosite.dat".into(),
        );
        let result = download_pair(&urls, &move |url: &str, max: usize| publisher.fetch(url, max)).unwrap();
        let (geosite, geoip) = (&result[0].1, &result[1].1);
        assert!(geosite.verified && geosite.codes == ["cn"] && geosite.version.as_deref() == Some("202609172350"));
        assert_eq!(geoip.sha256, sha256_hex(&ip));
        let mut mirror = Publisher::new(&[(&urls.geosite, &site), (&urls.geoip, &ip)]);
        mirror.sidecars = false;
        assert!(!download_pair(&urls, &move |url: &str, max: usize| mirror.fetch(url, max)).unwrap()[0].1.verified);
        let mut lying = Publisher::new(&[(&urls.geosite, &site), (&urls.geoip, &ip)]);
        lying.lying = true;
        let err = download_pair(&urls, &move |url: &str, max: usize| lying.fetch(url, max)).unwrap_err();
        assert!(err.to_string().contains("published sha256"));
        let garbage = Publisher::new(&[(&urls.geosite, &site), (&urls.geoip, b"garbage")]);
        let err = download_pair(&urls, &move |url: &str, max: usize| garbage.fetch(url, max)).unwrap_err();
        assert!(err.to_string().contains("geoip.dat"));
    }

    fn store(name: &str) -> (GeodataStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("xr-geo-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let seed = vec![("geosite".to_string(), dir.join("geosite.dat")), ("geoip".to_string(), dir.join("geoip.dat"))];
        (GeodataStore::new(dir.join("geo"), seed), dir)
    }

    fn clocked(store: &GeodataStore, now: Arc<Mutex<f64>>) {
        store.set_clock(Arc::new(move || *now.lock().unwrap()));
    }

    #[test]
    fn daily_updates_wait_for_the_update_hour_and_the_view_says_when() {
        let (store, _dir) = store("hour");
        let day = 1_790_000_000.0 - 1_790_000_000.0 % 86400.0;
        let now = Arc::new(Mutex::new(day + 2.0 * 3600.0 + 30.0));
        clocked(&store, now.clone());
        store.settings(Some(&Source::of("loyalsoldier")), Some(true), Some(&json!(24)), None).unwrap();
        let mut meta = store.meta();
        meta.insert("last_check_at".into(), Value::from(*now.lock().unwrap()));
        store.write_meta(&meta).unwrap();
        assert_eq!(store.view()["next_check_at"], json!(day + 86400.0 + 2.0 * 3600.0));
        *now.lock().unwrap() = day + 86400.0 + 2.0 * 3600.0 - 60.0;
        assert!(!store.due());
        *now.lock().unwrap() = day + 86400.0 + 2.0 * 3600.0 + 10.0;
        assert!(store.due());
        // A window missed (the host was down) waits for the next one: no restart in the daytime.
        *now.lock().unwrap() = day + 86400.0 + 9.0 * 3600.0;
        assert!(!store.due());
        assert_eq!(store.view()["next_check_at"], json!(day + 2.0 * 86400.0 + 2.0 * 3600.0));
        // Any hour when the owner clears the window; shorter intervals ignore it.
        store.settings(None, None, None, Some(&Value::Null)).unwrap();
        assert!(store.due());
        store.settings(None, None, Some(&json!(6)), Some(&json!(2))).unwrap();
        *now.lock().unwrap() = day + 86400.0 + 2.0 * 3600.0 + 6.0 * 3600.0 + 30.0;
        assert!(store.due());
        assert!(store.settings(None, None, None, Some(&json!(24))).unwrap_err().to_string().contains("update_hour"));
    }

    #[test]
    fn the_pin_follows_a_new_seed_after_an_xray_update() {
        let (store, dir) = store("follow");
        fs::write(dir.join("geosite.dat"), b"site-1").unwrap();
        fs::write(dir.join("geoip.dat"), b"ip-1").unwrap();
        store.ensure_seed().unwrap();
        store.settings(Some(&Source::of("xray")), Some(false), None, None).unwrap();
        assert!(!store.follow_seed().unwrap());
        // The version-agent put the new release's pair into the binary directory.
        fs::write(dir.join("geosite.dat"), b"site-2").unwrap();
        fs::write(dir.join("geoip.dat"), b"ip-2").unwrap();
        assert!(store.follow_seed().unwrap());
        assert_eq!(fs::read(store.path("geosite")).unwrap(), b"site-2");
        assert_eq!(store.meta()["origin"], "seed");
        // Downloaded lists are never replaced by the seed.
        store.settings(Some(&Source::of("loyalsoldier")), None, None, None).unwrap();
        fs::write(dir.join("geosite.dat"), b"site-3").unwrap();
        assert!(!store.follow_seed().unwrap());
    }

    fn answer(status: u16, reason: &str, location: Option<&str>, body: &[u8]) -> https::Response {
        let headers = location.map(|l| vec![("Location".to_string(), l.to_string())]).unwrap_or_default();
        https::Response { status, reason: reason.into(), headers, body: body.to_vec() }
    }

    /// GitHub's `releases/latest/download/<file>` carries the release tag on its first hop only;
    /// the last hop is a signed asset URL. The version comes from the hop that names it.
    #[test]
    fn fetch_reports_the_hop_that_names_the_release() {
        let hops = [
            "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202609172350/geosite.dat",
            "https://release-assets.githubusercontent.com/asset/abc?sig=xyz",
        ];
        let asked = Mutex::new(Vec::new());
        let send = |url: &https::Url| {
            asked.lock().unwrap().push(format!("{}{}", url.host, url.target));
            Ok(match asked.lock().unwrap().len() {
                1 => answer(302, "Found", Some(hops[0]), b""),
                2 => answer(302, "Found", Some(hops[1]), b""),
                _ => answer(200, "OK", None, b"geodata-bytes"),
            })
        };
        let start = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
        let (data, reported) = fetch_via(start, 100, &send).unwrap();
        assert_eq!((data.as_slice(), reported.as_str()), (&b"geodata-bytes"[..], hops[0]));
        assert_eq!(release_tag(&reported), Some("202609172350"));
        assert_eq!(asked.lock().unwrap()[2], "release-assets.githubusercontent.com/asset/abc?sig=xyz");
        // Off HTTPS, too large, empty, an HTTP error and a loop are refused as urllib refused them.
        let off =
            fetch_via(start, 100, &|_: &https::Url| Ok(answer(302, "Found", Some("http://plain.example/x"), b"")));
        assert_eq!(off.unwrap_err().to_string(), "redirected off https");
        let big = fetch_via(start, 3, &|_: &https::Url| Ok(answer(200, "OK", None, b"four")));
        assert_eq!(big.unwrap_err().code(), Some("geodata_too_large"));
        let empty = fetch_via(start, 3, &|_: &https::Url| Ok(answer(200, "OK", None, b"")));
        assert_eq!(empty.unwrap_err().to_string(), "empty file");
        let missing = fetch_via(start, 3, &|_: &https::Url| Ok(answer(404, "Not Found", None, b"")));
        assert_eq!(missing.unwrap_err().to_string(), "fetch failed: HTTP Error 404: Not Found");
        let looping =
            fetch_via(start, 3, &|url: &https::Url| Ok(answer(302, "Found", Some(&format!("{}x", url.target)), b"")));
        assert!(looping
            .unwrap_err()
            .to_string()
            .starts_with("fetch failed: HTTP Error 302: The HTTP server returned a redirect error"));
    }

    /// `geodata.fetch` over real TLS is the lab's business; here: what is refused before any
    /// connection, and an unreachable host as `geodata_fetch_failed`.
    #[test]
    fn fetch_refuses_plain_http_and_reports_an_unreachable_host() {
        assert!(
            matches!(fetch("http://example.com/x", 10), Err(Error::Geodata { code, .. }) if code == "geodata_invalid")
        );
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = fetch_with(&format!("https://127.0.0.1:{port}/geosite.dat"), 10, Duration::from_secs(2)).unwrap_err();
        assert_eq!(err.code(), Some("geodata_fetch_failed"));
        assert!(err.to_string().starts_with("fetch failed: <urlopen error [Errno 111]"), "{err}");
    }
}
