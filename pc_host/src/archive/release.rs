//! The reviewed external-artifact manifest (`release/external-artifacts.json`) and artifact
//! digests: a port of `installer/release.py:50-224`, `:425-449`, `:567-826`, `:980-1016` with the
//! exact `ReleaseError` texts.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use serde_json::{Map, Value};

use crate::fs::sha256_reader;
use crate::json::{loads_strict, JsonError};
use crate::pytext::{py_path_str, py_repr};
use crate::url;

/// `ReleaseError`: a release manifest or artifact failed closed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseError(pub String);

impl ReleaseError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        ReleaseError(message.into())
    }
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReleaseError {}

pub(crate) type Result<T> = std::result::Result<T, ReleaseError>;

/// The only architecture any pin is reviewed for (x86-64 VPS hosts).
pub const SUPPORTED_ARCHITECTURES: &[&str] = &["amd64"];
/// Licences a pinned artifact may carry.
pub const SUPPORTED_SPDX_LICENSES: &[&str] = &["Apache-2.0", "GPL-3.0-only", "GPL-3.0-or-later", "MPL-2.0"];
/// Upper bound of a reviewed zip member.
pub const DEFAULT_MAX_MEMBER_SIZE: u64 = 64 * 1024 * 1024;

/// One reviewed member of a zip artifact: what `safe_extract_zip` may write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPin {
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
}

/// One artifact for one architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPin {
    pub name: String,
    pub version: String,
    pub tag: String,
    pub repository: String,
    pub spdx_license: String,
    pub architecture: String,
    pub url: String,
    pub sha256: String,
    pub executable_path: Option<String>,
    pub executable_sha256: Option<String>,
    /// Zip artifacts: the members the installer extracts, nothing else.
    pub members: Option<Vec<(String, MemberPin)>>,
    /// The token the upstream file name carries for this architecture when it is not the
    /// Debian name (`Xray-linux-64.zip`).
    pub filename_architecture: Option<String>,
}

impl ArtifactPin {
    /// The pin of a member by name.
    pub fn member(&self, name: &str) -> Option<&MemberPin> {
        self.members.as_ref()?.iter().find(|(n, _)| n == name).map(|(_, pin)| pin)
    }
}

/// `ReleaseManifest`: the reviewed external artifacts with exact name and architecture lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub schema_version: i64,
    pub artifacts: BTreeMap<String, BTreeMap<String, ArtifactPin>>,
}

impl ReleaseManifest {
    /// `ReleaseManifest.from_bytes`: strict UTF-8 JSON (duplicate keys and `NaN`/`Infinity`
    /// refused), root keys exactly `{schema_version, artifacts}`, every artifact validated.
    pub fn from_bytes(data: &[u8]) -> Result<ReleaseManifest> {
        let document = match loads_strict(data) {
            Ok(document) => document,
            Err(JsonError::DuplicateKey(key)) => return Err(ReleaseError(format!("duplicate JSON key: {key}"))),
            Err(JsonError::Invalid(_)) => return Err(ReleaseError::new("manifest must be valid UTF-8 JSON")),
        };
        let root = require_object(&document, "manifest")?;
        require_keys(root, &["schema_version", "artifacts"], "manifest")?;
        if root["schema_version"].as_i64() != Some(1) || !root["schema_version"].is_i64() {
            return Err(ReleaseError::new("schema_version must be the integer 1"));
        }
        let raw_artifacts = match &root["artifacts"] {
            Value::Array(items) if !items.is_empty() => items,
            _ => return Err(ReleaseError::new("artifacts must be a non-empty array")),
        };
        let mut artifacts = BTreeMap::new();
        for (index, raw) in raw_artifacts.iter().enumerate() {
            let (name, platforms) = parse_artifact(raw, index)?;
            if artifacts.contains_key(&name) {
                return Err(ReleaseError(format!("duplicate artifact: {name}")));
            }
            artifacts.insert(name, platforms);
        }
        Ok(ReleaseManifest { schema_version: 1, artifacts })
    }

    /// `external_artifact(name, arch)` / `ExternalArtifact.for_platform`.
    pub fn external_artifact(&self, name: &str, arch: &str) -> Result<&ArtifactPin> {
        if !SUPPORTED_ARCHITECTURES.contains(&arch) {
            return Err(ReleaseError(format!("unsupported architecture: {arch}")));
        }
        let artifact = self.artifacts.get(name).ok_or_else(|| ReleaseError(format!("unknown artifact: {name}")))?;
        artifact.get(arch).ok_or_else(|| {
            ReleaseError(format!("artifact {} has no pin for architecture {}", py_repr(name), py_repr(arch)))
        })
    }
}

fn require_object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| ReleaseError(format!("{label} must be an object")))
}

fn require_keys(value: &Map<String, Value>, expected: &[&str], label: &str) -> Result<()> {
    if let Some(unknown) = value.keys().find(|key| !expected.contains(&key.as_str())) {
        return Err(ReleaseError(format!("unknown {label} key: {unknown}")));
    }
    let mut missing: Vec<&&str> = expected.iter().filter(|key| !value.contains_key(**key)).collect();
    missing.sort();
    if let Some(key) = missing.first() {
        return Err(ReleaseError(format!("missing {label} key: {key}")));
    }
    Ok(())
}

fn require_string<'a>(value: &'a Value, label: &str) -> Result<&'a str> {
    match value {
        Value::String(text) if !text.is_empty() => Ok(text),
        _ => Err(ReleaseError(format!("{label} must be a non-empty string"))),
    }
}

/// `_require_sha256`: exactly 64 lowercase hex digits.
pub fn require_sha256(value: &str, label: &str) -> Result<()> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(ReleaseError(format!("{label} must be an exact lowercase SHA-256")))
    }
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z')) && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_semver(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_repository(value: &str) -> bool {
    let token =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    match value.split_once('/') {
        Some((owner, project)) => token(owner) && token(project),
        None => false,
    }
}

/// `_MEMBER_NAME_RE`: `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`.
pub(crate) fn is_member_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..].iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn parse_artifact(value: &Value, index: usize) -> Result<(String, BTreeMap<String, ArtifactPin>)> {
    let artifact = require_object(value, &format!("artifact {index}"))?;
    require_keys(artifact, &["name", "version", "tag", "repository", "spdx_license", "platforms"], "artifact")?;
    let name = require_string(&artifact["name"], "artifact name")?;
    if !is_name(name) {
        return Err(ReleaseError(format!("invalid artifact name: {name}")));
    }
    let version = require_string(&artifact["version"], &format!("artifact {name} version"))?;
    if !is_semver(version) {
        return Err(ReleaseError(format!("artifact {name} version must be semantic x.y.z")));
    }
    let tag = require_string(&artifact["tag"], &format!("artifact {name} tag"))?;
    if tag != format!("v{version}") {
        return Err(ReleaseError(format!("artifact {name} tag must equal v{version}")));
    }
    let repository = require_string(&artifact["repository"], &format!("artifact {name} repository"))?;
    if !is_repository(repository) {
        return Err(ReleaseError(format!("artifact {name} repository is invalid")));
    }
    let spdx_license = require_string(&artifact["spdx_license"], &format!("artifact {name} SPDX license"))?;
    if !SUPPORTED_SPDX_LICENSES.contains(&spdx_license) {
        return Err(ReleaseError(format!("unsupported SPDX license: {spdx_license}")));
    }
    let raw_platforms = require_object(&artifact["platforms"], &format!("artifact {name} platforms"))?;
    let mut keys: Vec<&str> = raw_platforms.keys().map(String::as_str).collect();
    keys.sort();
    if keys != SUPPORTED_ARCHITECTURES {
        return Err(ReleaseError(format!(
            "artifact {name} platforms must be exactly: {}",
            SUPPORTED_ARCHITECTURES.join(", ")
        )));
    }
    let mut platforms = BTreeMap::new();
    for architecture in SUPPORTED_ARCHITECTURES {
        let identity = Identity { name, version, tag, repository, spdx_license, architecture };
        platforms.insert(architecture.to_string(), parse_platform_pin(&raw_platforms[*architecture], &identity)?);
    }
    Ok((name.to_string(), platforms))
}

struct Identity<'a> {
    name: &'a str,
    version: &'a str,
    tag: &'a str,
    repository: &'a str,
    spdx_license: &'a str,
    architecture: &'a str,
}

fn parse_platform_pin(value: &Value, identity: &Identity) -> Result<ArtifactPin> {
    let name = identity.name;
    let architecture = identity.architecture;
    let pin = require_object(value, &format!("artifact {name} platform {architecture}"))?;
    let required = ["architecture", "url", "sha256"];
    let optional = ["executable_path", "executable_sha256", "members", "filename_architecture"];
    if let Some(unknown) = pin.keys().find(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str())) {
        return Err(ReleaseError(format!("unknown platform key: {unknown}")));
    }
    let mut missing: Vec<&&str> = required.iter().filter(|k| !pin.contains_key(**k)).collect();
    missing.sort();
    if let Some(key) = missing.first() {
        return Err(ReleaseError(format!("missing platform key: {key}")));
    }
    let declared = require_string(&pin["architecture"], &format!("artifact {name} architecture"))?;
    if declared != architecture {
        return Err(ReleaseError(format!(
            "platform mismatch: key {}, value {}",
            py_repr(architecture),
            py_repr(declared)
        )));
    }
    let mut filename_architecture = None;
    if let Some(raw) = pin.get("filename_architecture") {
        let token = require_string(raw, &format!("artifact {name} filename_architecture"))?;
        let valid = (1..=16).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid {
            return Err(ReleaseError(format!("artifact {name} filename_architecture is invalid")));
        }
        filename_architecture = Some(token.to_string());
    }
    let url = require_string(&pin["url"], &format!("artifact {name} URL"))?;
    validate_release_url(
        url,
        identity.repository,
        identity.tag,
        filename_architecture.as_deref().unwrap_or(architecture),
    )?;
    let sha256 = require_string(&pin["sha256"], &format!("artifact {name} SHA-256"))?;
    require_sha256(sha256, &format!("artifact {name}"))?;
    let members = match pin.get("members") {
        Some(raw) => Some(parse_members(raw, name)?),
        None => None,
    };
    let has_path = pin.contains_key("executable_path");
    if has_path != pin.contains_key("executable_sha256") {
        return Err(ReleaseError::new("executable_path and executable_sha256 must be supplied together"));
    }
    let (mut executable_path, mut executable_sha256) = (None, None);
    if has_path {
        let path = require_string(&pin["executable_path"], &format!("artifact {name} executable path"))?;
        if normalize_archive_path(path)? != path {
            return Err(ReleaseError(format!("artifact {name} executable path must be canonical")));
        }
        let digest = require_string(&pin["executable_sha256"], &format!("artifact {name} executable SHA-256"))?;
        require_sha256(digest, &format!("artifact {name} executable"))?;
        executable_path = Some(path.to_string());
        executable_sha256 = Some(digest.to_string());
    }
    Ok(ArtifactPin {
        name: name.into(),
        version: identity.version.into(),
        tag: identity.tag.into(),
        repository: identity.repository.into(),
        spdx_license: identity.spdx_license.into(),
        architecture: architecture.into(),
        url: url.into(),
        sha256: sha256.into(),
        executable_path,
        executable_sha256,
        members,
        filename_architecture,
    })
}

fn parse_members(value: &Value, artifact: &str) -> Result<Vec<(String, MemberPin)>> {
    let raw = require_object(value, &format!("artifact {artifact} members"))?;
    if raw.is_empty() {
        return Err(ReleaseError(format!("artifact {artifact} members must name at least one member")));
    }
    let mut members = Vec::new();
    for (member, raw_pin) in raw {
        if !is_member_name(member) || member == "." || member == ".." {
            return Err(ReleaseError(format!(
                "artifact {artifact} member name is not a plain file name: {}",
                py_repr(member)
            )));
        }
        let entry = require_object(raw_pin, &format!("artifact {artifact} member {member}"))?;
        let mut keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        keys.sort();
        if keys != ["mode", "sha256", "size"] {
            return Err(ReleaseError(format!("artifact {artifact} member {member} must carry sha256, size and mode")));
        }
        let sha256 = require_string(&entry["sha256"], &format!("artifact {artifact} member {member} SHA-256"))?;
        require_sha256(sha256, &format!("artifact {artifact} member {member}"))?;
        let size = match &entry["size"] {
            Value::Number(n) if n.is_u64() || n.is_i64() => n.as_i64().unwrap_or(-1),
            _ => -1,
        };
        if !(1..=DEFAULT_MAX_MEMBER_SIZE as i64).contains(&size) {
            return Err(ReleaseError(format!("artifact {artifact} member {member} size is out of bounds")));
        }
        let mode = require_string(&entry["mode"], &format!("artifact {artifact} member {member} mode"))?;
        let plain_octal =
            mode.len() == 4 && mode.starts_with('0') && mode[1..].bytes().all(|b| (b'0'..=b'7').contains(&b));
        if !plain_octal {
            return Err(ReleaseError(format!("artifact {artifact} member {member} mode must be a plain octal mode")));
        }
        let mode = u32::from_str_radix(mode, 8).expect("validated octal");
        members.push((member.clone(), MemberPin { sha256: sha256.into(), size: size as u64, mode }));
    }
    Ok(members)
}

/// `_validate_release_url`: canonical ASCII `https://github.com/<owner>/<repo>/releases/download/
/// <tag>/<file>` with the architecture token in the file name.
pub fn validate_release_url(url: &str, repository: &str, tag: &str, architecture: &str) -> Result<()> {
    if !url.is_ascii() {
        return Err(ReleaseError::new("artifact URL must use canonical ASCII"));
    }
    if url.chars().any(|c| c.is_whitespace() || (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(ReleaseError::new("artifact URL must not contain whitespace or control characters"));
    }
    let parsed = url::split(url);
    if parsed.scheme != "https" {
        return Err(ReleaseError::new("artifact URL must use HTTPS"));
    }
    if parsed.netloc != "github.com" {
        return Err(ReleaseError::new("artifact URL must use the official GitHub host"));
    }
    if !parsed.query.is_empty() || !parsed.fragment.is_empty() {
        return Err(ReleaseError::new("artifact URL must not contain a query or fragment"));
    }
    if url != format!("https://github.com{}", parsed.path) {
        return Err(ReleaseError::new("artifact URL must use exact canonical form"));
    }
    if parsed.path.to_lowercase().contains("latest") {
        return Err(ReleaseError::new("artifact URL must be an immutable release URL"));
    }
    if parsed.path.contains('%') || parsed.path.contains('\\') {
        return Err(ReleaseError::new("artifact URL path must be canonical"));
    }
    let (owner, project) = repository.split_once('/').unwrap_or((repository, ""));
    let parts: Vec<&str> = parsed.path.split('/').collect();
    if parts.len() != 7 || parts[..6] != ["", owner, project, "releases", "download", tag] {
        return Err(ReleaseError::new("artifact URL repository and tag must match the reviewed artifact"));
    }
    let filename = parts[6];
    if filename.is_empty() || !has_architecture_token(filename, architecture) {
        return Err(ReleaseError(format!("artifact URL filename must match architecture {architecture}")));
    }
    Ok(())
}

/// `(?:^|[-_.])<arch>(?:[-_.]|$)` searched in `filename`.
fn has_architecture_token(filename: &str, architecture: &str) -> bool {
    let separator = |b: u8| matches!(b, b'-' | b'_' | b'.');
    let bytes = filename.as_bytes();
    let mut start = 0;
    while let Some(offset) = filename[start..].find(architecture) {
        let at = start + offset;
        let end = at + architecture.len();
        let before = at == 0 || separator(bytes[at - 1]);
        let after = end == bytes.len() || separator(bytes[end]);
        if before && after {
            return true;
        }
        start = at + 1;
        if start >= filename.len() {
            break;
        }
    }
    false
}

/// `_normalize_archive_path`: a relative POSIX path without `..`, NUL or backslash, returned in
/// `PurePosixPath` form (`./a//b` → `a/b`).
pub fn normalize_archive_path(value: &str) -> Result<String> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') {
        return Err(ReleaseError(format!("unsafe archive path: {}", py_repr(value))));
    }
    if value.starts_with('/') || value.split('/').any(|part| part == "..") {
        return Err(ReleaseError(format!("unsafe archive path: {value}")));
    }
    let normalized: Vec<&str> = value.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if normalized.is_empty() {
        return Err(ReleaseError(format!("unsafe archive path: {value}")));
    }
    Ok(normalized.join("/"))
}

/// `_resolve_symlink_target`: where a relative symlink inside the archive points, refusing
/// absolute targets and any escape above the archive root.
pub fn resolve_symlink_target(member_path: &str, target: &str) -> Result<String> {
    if target.is_empty() || target.contains('\0') || target.contains('\\') || target.starts_with('/') {
        return Err(ReleaseError(format!("unsafe symlink target for {member_path}: {}", py_repr(target))));
    }
    let mut parts: Vec<&str> = member_path.split('/').filter(|p| !p.is_empty()).collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(ReleaseError(format!("unsafe symlink target for {member_path}: {target}")));
                }
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err(ReleaseError(format!("unsafe symlink target for {member_path}: {target}")));
    }
    Ok(parts.join("/"))
}

/// `_open_regular_file`: `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`, and it must be a regular file.
pub(crate) fn open_regular_file(path: &Path, label: &str) -> Result<File> {
    let not_regular = || ReleaseError(format!("{label} is not a regular file: {}", py_path_str(path)));
    let name =
        std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).map_err(|_| not_regular())?;
    // SAFETY: valid C string; the descriptor is owned by the File below.
    let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(not_regular());
    }
    // SAFETY: fresh descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    match super::dirfd::fstat(file.as_raw_fd()) {
        Ok(stat) if super::dirfd::is_regular(&stat) => Ok(file),
        _ => Err(not_regular()),
    }
}

/// `verify_artifact`: stream one no-follow descriptor and compare the reviewed SHA-256.
pub fn verify_artifact(path: &Path, expected_sha256: &str) -> Result<()> {
    require_sha256(expected_sha256, "expected artifact")?;
    let mut file = open_regular_file(path, "artifact")?;
    let actual = sha256_reader(&mut file as &mut dyn Read)
        .map_err(|_| ReleaseError(format!("could not read artifact: {}", py_path_str(path))))?;
    if !crate::constant_time_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        return Err(ReleaseError(format!(
            "artifact digest mismatch for {name}: expected {expected_sha256}, got {actual}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_paths_normalise_like_pure_posix_path() {
        assert_eq!(normalize_archive_path("./pkg//app/").unwrap(), "pkg/app");
        assert_eq!(normalize_archive_path("/etc/shadow").unwrap_err().0, "unsafe archive path: /etc/shadow");
        assert_eq!(normalize_archive_path("safe/../escape").unwrap_err().0, "unsafe archive path: safe/../escape");
        assert_eq!(normalize_archive_path("a\\b").unwrap_err().0, "unsafe archive path: 'a\\\\b'");
        assert_eq!(normalize_archive_path("").unwrap_err().0, "unsafe archive path: ''");
        assert_eq!(normalize_archive_path("./").unwrap_err().0, "unsafe archive path: ./");
    }

    #[test]
    fn symlink_targets_stay_inside() {
        assert_eq!(resolve_symlink_target("pkg/current", "app").unwrap(), "pkg/app");
        assert_eq!(resolve_symlink_target("pkg/a/b", "../c").unwrap(), "pkg/c");
        assert_eq!(
            resolve_symlink_target("pkg/current", "/etc/shadow").unwrap_err().0,
            "unsafe symlink target for pkg/current: '/etc/shadow'"
        );
        assert_eq!(
            resolve_symlink_target("pkg/current", "../../outside").unwrap_err().0,
            "unsafe symlink target for pkg/current: ../../outside"
        );
        assert!(resolve_symlink_target("pkg/current", "..").is_err());
    }

    #[test]
    fn architecture_token() {
        assert!(has_architecture_token("mita_3.38.1_amd64.deb", "amd64"));
        assert!(has_architecture_token("Xray-linux-64.zip", "64"));
        assert!(!has_architecture_token("mita_3.38.1_arm64.deb", "amd64"));
        assert!(!has_architecture_token("x-ui-linux-amd643.tar.gz", "amd64"));
        assert!(has_architecture_token("amd64", "amd64"));
    }

    #[test]
    fn release_url_rules() {
        let ok = "https://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb";
        assert!(validate_release_url(ok, "enfein/mieru", "v3.38.1", "amd64").is_ok());
        let check = |url: &str| validate_release_url(url, "enfein/mieru", "v3.38.1", "amd64").unwrap_err().0;
        assert_eq!(
            check("HTTPS://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb"),
            "artifact URL must use exact canonical form"
        );
        assert_eq!(check(&format!("{ok}?raw=1")), "artifact URL must not contain a query or fragment");
        assert_eq!(check(&format!(" {ok}")), "artifact URL must not contain whitespace or control characters");
        assert_eq!(
            check("https://github.com/enfein/mieru/releases/latest/download/mita_3.38.1_amd64.deb"),
            "artifact URL must be an immutable release URL"
        );
        assert_eq!(
            check("https://github.com/enfein/mieru/releases/download/v3.38.1/mita%2e_amd64.deb"),
            "artifact URL path must be canonical"
        );
        assert_eq!(
            check("https://github.com:443/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb"),
            "artifact URL must use the official GitHub host"
        );
        assert_eq!(
            check("https://github.com/enfein/mieru/releases/download/v3.38.1/é"),
            "artifact URL must use canonical ASCII"
        );
    }
}
