//! The root-owned catalog of approved artifacts (`/etc/proxy-control/versions.json`) and the
//! validation every cached upstream candidate goes through (`version_agent/catalog.py`).
//!
//! The Python regexes are hand-written validators here; `\d` is ASCII (Python's matched every
//! Unicode decimal digit — DIFFERENCES).

use std::path::Path;

use serde_json::{Map, Value};

use crate::errors::CatalogError;

/// `_COMPONENTS`, in the order the catalog is validated.
pub const COMPONENTS: [&str; 7] = ["telemt", "naive", "mita", "xray", "panel", "amneziawg", "trusttunnel"];
/// `XRAY_MEMBERS`.
pub const XRAY_MEMBERS: [&str; 3] = ["xray", "geoip.dat", "geosite.dat"];
pub const TRUSTTUNNEL_REPOSITORY: &str = "TrustTunnel/TrustTunnel";

/// `CatalogEntry`.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogEntry {
    pub component: String,
    pub version: String,
    pub kind: String,
    pub image: Option<String>,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub runtime_version: Option<String>,
    /// `{"format", "member"}` or `{"format", "members": {xray, geoip.dat, geosite.dat}}`.
    pub archive: Option<Map<String, Value>>,
    /// `catalog` or `upstream`.
    pub source: String,
    /// naive `{caddy_version, builder_image, forwardproxy_commit}`, amneziawg `{commit, tag}`.
    pub build: Option<Map<String, Value>>,
    pub base_image: Option<String>,
}

impl CatalogEntry {
    fn new(component: &str, version: &str, kind: &str, source: &str) -> Self {
        CatalogEntry {
            component: component.into(),
            version: version.into(),
            kind: kind.into(),
            image: None,
            url: None,
            sha256: None,
            runtime_version: None,
            archive: None,
            source: source.into(),
            build: None,
            base_image: None,
        }
    }

    /// `public()`: what the Versions screen sees (no `runtime_version`).
    pub fn public(&self) -> Map<String, Value> {
        let mut result = Map::new();
        result.insert("version".into(), self.version.clone().into());
        result.insert("kind".into(), self.kind.clone().into());
        result.insert("source".into(), self.source.clone().into());
        for (key, value) in
            [("image", &self.image), ("base_image", &self.base_image), ("url", &self.url), ("sha256", &self.sha256)]
        {
            if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
                result.insert(key.into(), value.clone().into());
            }
        }
        if let Some(archive) = self.archive.as_ref().filter(|a| !a.is_empty()) {
            result.insert("archive".into(), Value::Object(archive.clone()));
        }
        if let Some(build) = self.build.as_ref().filter(|b| !b.is_empty()) {
            result.insert("build".into(), Value::Object(build.clone()));
        }
        result
    }
}

/// `Catalog`: the validated entries per component, in catalog order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Catalog {
    pub components: Vec<(String, Vec<CatalogEntry>)>,
}

impl Catalog {
    pub fn entries(&self, component: &str) -> &[CatalogEntry] {
        self.components.iter().find(|(name, _)| name == component).map(|(_, entries)| entries.as_slice()).unwrap_or(&[])
    }

    /// `Catalog.entry`.
    pub fn entry(&self, component: &str, version: &str) -> Result<&CatalogEntry, CatalogError> {
        self.entries(component)
            .iter()
            .find(|item| item.version == version)
            .ok_or_else(|| CatalogError(format!("version is not approved for {component}")))
    }
}

fn alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// `_VERSION`: `^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`.
pub fn is_version(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(alnum)
        && text.len() <= 64
        && chars.all(|c| alnum(c) || matches!(c, '.' | '_' | '+' | ':' | '-'))
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_SHA256`.
pub fn is_sha256(text: &str) -> bool {
    is_hex(text, 64)
}

/// `_HEX40`.
pub fn is_hex40(text: &str) -> bool {
    is_hex(text, 40)
}

/// `_RUNTIME_VERSION`: 1–160 characters, no CR or LF.
pub fn is_runtime_version(text: &str) -> bool {
    let count = text.chars().count();
    (1..=160).contains(&count) && !text.contains(['\r', '\n'])
}

/// `_IMAGE`: `^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$`.
pub fn is_image(text: &str) -> bool {
    const SUFFIX: usize = "@sha256:".len() + 64;
    if text.len() <= SUFFIX || !text.is_char_boundary(text.len() - SUFFIX) {
        return false;
    }
    let (prefix, suffix) = text.split_at(text.len() - SUFFIX);
    let mut chars = prefix.chars();
    suffix.starts_with("@sha256:")
        && is_sha256(&suffix[8..])
        && chars.next().is_some_and(alnum)
        && chars.all(|c| alnum(c) || matches!(c, '.' | '_' | '/' | '@' | ':' | '-'))
}

/// `TELEMT_BASE_IMAGE`.
pub fn is_telemt_base_image(text: &str) -> bool {
    text.strip_prefix("ghcr.io/samnet-dev/mtproxymax-telemt@sha256:").is_some_and(is_sha256)
}

fn is_number(text: &str) -> bool {
    pc_common::pytext::is_ascii_digits(text)
}

/// `^\d+(?:\.\d+){1,3}$` (`TELEMT_RELEASE_VERSION`, `AMNEZIAWG_VERSION`, upstream
/// `_RELEASE_VERSION`), ASCII digits.
pub fn is_dotted(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    (2..=4).contains(&parts.len()) && parts.iter().all(|p| is_number(p))
}

/// `TRUSTTUNNEL_VERSION`: dotted digits with an optional `-ident(.ident)*` suffix.
pub fn is_trusttunnel_version(text: &str) -> bool {
    let (core, suffix) = match text.split_once('-') {
        Some((core, suffix)) => (core, Some(suffix)),
        None => (text, None),
    };
    is_dotted(core)
        && suffix.is_none_or(|suffix| {
            suffix.split('.').all(|ident| !ident.is_empty() && ident.chars().all(|c| c.is_ascii_alphanumeric()))
        })
}

/// `_MEMBER` plus "no `..` segment".
pub fn is_member(text: &str) -> bool {
    text.split('/').all(|segment| {
        let mut chars = segment.chars();
        chars.next().is_some_and(alnum) && chars.all(|c| alnum(c) || matches!(c, '.' | '_' | '-'))
    }) && !text.split('/').any(|segment| segment == "..")
}

fn reject_unknown(mapping: &Map<String, Value>, allowed: &[&str], label: &str) -> Result<(), CatalogError> {
    // serde_json's map is sorted, so the first unknown key is `sorted(unknown)[0]`.
    match mapping.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(CatalogError(format!("unknown {label} field: {key}"))),
        None => Ok(()),
    }
}

fn archive(component: &str, raw: Option<&Value>) -> Result<Option<Map<String, Value>>, CatalogError> {
    let raw = match raw {
        None | Some(Value::Null) => return Ok(None),
        Some(raw) => raw,
    };
    let Some(map) =
        raw.as_object().filter(|map| matches!(map.get("format").and_then(Value::as_str), Some("zip" | "tar.gz")))
    else {
        return Err(CatalogError::new("unsupported archive format"));
    };
    reject_unknown(map, &["format", "member", "members"], "archive")?;
    let member = map.get("member").filter(|v| !v.is_null());
    let members = map.get("members").filter(|v| !v.is_null());
    if member.is_none() == members.is_none() {
        return Err(CatalogError::new("archive needs member or members"));
    }
    if component == "xray" && members.is_none() {
        return Err(CatalogError::new("xray archive must name its members"));
    }
    if component != "xray" && members.is_some() {
        return Err(CatalogError(format!("{component} archive must name a single member")));
    }
    let names: Vec<&Value> = match members {
        Some(members) => {
            let Some(set) = members.as_object().filter(|set| {
                set.len() == XRAY_MEMBERS.len() && XRAY_MEMBERS.iter().all(|name| set.contains_key(*name))
            }) else {
                return Err(CatalogError::new("invalid archive member set"));
            };
            set.values().collect()
        }
        None => vec![member.expect("member is set")],
    };
    if !names.iter().all(|name| name.as_str().is_some_and(is_member)) {
        return Err(CatalogError::new("invalid archive member"));
    }
    let mut result = Map::new();
    result.insert("format".into(), map["format"].clone());
    match (member, members) {
        (Some(member), _) => result.insert("member".into(), member.clone()),
        (None, Some(members)) => result.insert("members".into(), members.clone()),
        (None, None) => None,
    };
    Ok(Some(result))
}

fn naive_build(raw: Option<&Value>) -> Result<Map<String, Value>, CatalogError> {
    let Some(map) = raw.and_then(Value::as_object) else {
        return Err(CatalogError::new("build entry must be an object"));
    };
    reject_unknown(map, &["caddy_version", "builder_image", "forwardproxy_commit"], "build")?;
    let version = map.get("caddy_version").and_then(Value::as_str);
    let image = map.get("builder_image").and_then(Value::as_str);
    let commit = map.get("forwardproxy_commit").and_then(Value::as_str);
    match (version, image, commit) {
        (Some(version), Some(image), Some(commit))
            if is_version(version) && is_image(image) && image.starts_with("caddy:") && is_hex40(commit) =>
        {
            let mut build = Map::new();
            build.insert("caddy_version".into(), version.into());
            build.insert("builder_image".into(), image.into());
            build.insert("forwardproxy_commit".into(), commit.into());
            Ok(build)
        }
        _ => Err(CatalogError::new(
            "build entry must pin caddy_version, a caddy builder image digest and a forwardproxy commit",
        )),
    }
}

/// `urlsplit(url)` checks of an artifact URL: HTTPS, a host, no credentials, query or fragment.
pub fn is_plain_https(url: &str) -> bool {
    let parts = pc_host::url::split(url);
    parts.scheme == "https"
        && parts.hostname().is_some_and(|host| !host.is_empty())
        && !parts.username().is_some_and(|user| !user.is_empty())
        && !parts.password().is_some_and(|password| !password.is_empty())
        && parts.query.is_empty()
        && parts.fragment.is_empty()
}

fn https_artifact(raw: &Map<String, Value>, label: &str) -> Result<(String, String), CatalogError> {
    let url = raw.get("url").and_then(Value::as_str);
    if !url.is_some_and(is_plain_https) {
        return Err(CatalogError(format!("{label} artifact URL must be HTTPS without credentials or query")));
    }
    let digest = raw.get("sha256").and_then(Value::as_str);
    if !digest.is_some_and(is_sha256) {
        return Err(CatalogError(format!("{label} artifact must have a lowercase SHA-256")));
    }
    Ok((url.unwrap_or_default().to_string(), digest.unwrap_or_default().to_string()))
}

const ENTRY_KEYS: [&str; 10] =
    ["version", "kind", "image", "url", "sha256", "runtime_version", "archive", "source", "build", "base_image"];

fn entry(component: &str, raw: &Value) -> Result<CatalogEntry, CatalogError> {
    let Some(raw) = raw.as_object() else {
        return Err(CatalogError(format!("{component} catalog entry must be an object")));
    };
    reject_unknown(raw, &ENTRY_KEYS, "catalog")?;
    let Some(version) = raw.get("version").and_then(Value::as_str).filter(|v| is_version(v)) else {
        return Err(CatalogError(format!("invalid version for {component}")));
    };
    let kind = raw.get("kind");
    let runtime_version = match raw.get("runtime_version") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if is_runtime_version(text) => Some(text.clone()),
        Some(_) => return Err(CatalogError(format!("invalid runtime_version for {component}"))),
    };
    let source = match raw.get("source") {
        None => "catalog",
        Some(Value::String(text)) if text == "catalog" || text == "upstream" => text.as_str(),
        Some(_) => return Err(CatalogError(format!("invalid source for {component}"))),
    };
    let kind = kind.and_then(Value::as_str).unwrap_or("\u{0}not a kind");
    let mut result = CatalogEntry::new(component, version, kind, source);
    match (kind, component) {
        ("image", _) => {
            reject_unknown(raw, &["version", "kind", "image", "runtime_version", "source"], "image")?;
            let Some(image) = raw.get("image").and_then(Value::as_str).filter(|i| is_image(i)) else {
                return Err(CatalogError::new("telemt image must use an immutable image digest"));
            };
            result.image = Some(image.into());
            result.runtime_version = runtime_version;
        }
        ("release", "panel") => {
            reject_unknown(raw, &["version", "kind", "url", "sha256", "source"], "release")?;
            let (url, digest) = https_artifact(raw, "release")?;
            result.url = Some(url);
            result.sha256 = Some(digest);
        }
        ("binary", c) if c != "panel" => {
            reject_unknown(
                raw,
                &["version", "kind", "url", "sha256", "runtime_version", "archive", "source"],
                "binary",
            )?;
            let (url, digest) = https_artifact(raw, "binary")?;
            result.url = Some(url);
            result.sha256 = Some(digest);
            result.runtime_version = runtime_version;
            result.archive = archive(component, raw.get("archive"))?;
        }
        ("build", "naive") => {
            reject_unknown(raw, &["version", "kind", "build", "runtime_version", "source"], "build")?;
            result.runtime_version = runtime_version;
            result.build = Some(naive_build(raw.get("build"))?);
        }
        ("build", "telemt") => {
            reject_unknown(raw, &["version", "kind", "base_image", "url", "sha256", "source"], "telemt build")?;
            if !is_dotted(version) {
                return Err(CatalogError::new("telemt build version must be dotted digits"));
            }
            let Some(base) = raw.get("base_image").and_then(Value::as_str).filter(|b| is_telemt_base_image(b)) else {
                return Err(CatalogError::new("telemt build must use the mtproxymax-telemt image by digest"));
            };
            let (url, digest) = https_artifact(raw, "telemt build")?;
            if url != format!("https://github.com/telemt/telemt/releases/download/{version}/telemt") {
                return Err(CatalogError::new("telemt build must download the telemt/telemt release binary"));
            }
            result.url = Some(url);
            result.sha256 = Some(digest);
            result.base_image = Some(base.into());
        }
        ("build", "amneziawg") => {
            reject_unknown(raw, &["version", "kind", "build", "source"], "amneziawg build")?;
            if !is_dotted(version) {
                return Err(CatalogError::new("amneziawg build version must be dotted digits"));
            }
            let Some(build) = raw.get("build").and_then(Value::as_object) else {
                return Err(CatalogError::new("amneziawg build entry must be an object"));
            };
            reject_unknown(build, &["commit", "tag"], "amneziawg build")?;
            let commit = build.get("commit").and_then(Value::as_str).filter(|c| is_hex40(c));
            let tag_ok = build.get("tag").and_then(Value::as_str) == Some(format!("v{version}").as_str());
            let Some(commit) = commit.filter(|_| tag_ok) else {
                return Err(CatalogError::new("amneziawg build must pin the commit of tag v<version>"));
            };
            let mut pinned = Map::new();
            pinned.insert("commit".into(), commit.into());
            pinned.insert("tag".into(), format!("v{version}").into());
            result.build = Some(pinned);
        }
        ("build", "trusttunnel") => {
            reject_unknown(raw, &["version", "kind", "url", "sha256", "source"], "trusttunnel build")?;
            if !is_trusttunnel_version(version) {
                return Err(CatalogError::new("trusttunnel build version is malformed"));
            }
            let (url, digest) = https_artifact(raw, "trusttunnel build")?;
            let expected = format!(
                "https://github.com/{TRUSTTUNNEL_REPOSITORY}/releases/download/v{version}/trusttunnel-v{version}-linux-x86_64.tar.gz"
            );
            if url != expected {
                return Err(CatalogError::new(
                    "trusttunnel build must download the TrustTunnel x86_64 release archive",
                ));
            }
            result.url = Some(url);
            result.sha256 = Some(digest);
        }
        _ => return Err(CatalogError(format!("unsupported artifact kind for {component}"))),
    }
    Ok(result)
}

/// `entry_from_dict`: one entry validated the way the catalog does (cached upstream candidates).
pub fn entry_from_value(component: &str, raw: &Value) -> Result<CatalogEntry, CatalogError> {
    if !COMPONENTS.contains(&component) {
        return Err(CatalogError::new("unknown version catalog component"));
    }
    entry(component, raw)
}

/// `load_catalog` over bytes already read.
pub fn parse_catalog(data: &[u8]) -> Result<Catalog, CatalogError> {
    let raw = pc_host::json::loads(data).map_err(|_| CatalogError::new("version catalog unavailable"))?;
    let Some(raw) = raw.as_object() else {
        return Err(CatalogError::new("version catalog must be an object"));
    };
    reject_unknown(raw, &["schema", "components"], "catalog root")?;
    let components = raw.get("components").and_then(Value::as_object);
    let Some(components) = components.filter(|_| raw.get("schema").is_some_and(crate::py::equals_one)) else {
        return Err(CatalogError::new("unsupported version catalog schema"));
    };
    if components.keys().any(|key| !COMPONENTS.contains(&key.as_str())) {
        return Err(CatalogError::new("unknown version catalog component"));
    }
    let mut result = Vec::new();
    for component in COMPONENTS {
        let values = match components.get(component) {
            None => Vec::new(),
            Some(Value::Array(values)) => {
                values.iter().map(|value| entry(component, value)).collect::<Result<_, _>>()?
            }
            Some(_) => return Err(CatalogError(format!("{component} catalog must be a list"))),
        };
        let mut seen = std::collections::BTreeSet::new();
        if !values.iter().all(|item: &CatalogEntry| seen.insert(item.version.clone())) {
            return Err(CatalogError(format!("duplicate {component} version")));
        }
        result.push((component.to_string(), values));
    }
    Ok(Catalog { components: result })
}

/// `load_catalog(path)`.
pub fn load_catalog(path: &Path) -> Result<Catalog, CatalogError> {
    let data = std::fs::read(path).map_err(|_| CatalogError::new("version catalog unavailable"))?;
    parse_catalog(&data)
}

#[cfg(test)]
mod tests;
