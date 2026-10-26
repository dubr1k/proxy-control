//! What a built release says about itself: `release/release.json` inside the tree
//! (`installer/cli.py:138-160`) and the published `release-manifest.json`
//! (`release/build.py:298-308`, checked by `install-release.sh`).
//!
//! `release.json` gains two keys additively in 4.0, keeping `schema: 1` (host inventory §9.1):
//! `binaries` (tree path → sha256 of the prebuilt host binaries) and `builder` (`image`,
//! `target`, `rustc`). Readers ignore keys they do not know, as Python's did.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{Map, Value};

use super::release::{is_sha256, normalize_archive_path};
use crate::json::loads;

/// Where the identity lives in a release tree.
pub const IDENTITY_PATH: &str = "release/release.json";
/// The installer binary inside a release tree.
pub const INSTALLER_BINARY: &str = "installer/bin/linux-amd64/proxy-control-installer";
/// The version-agent binary inside a release tree.
pub const AGENT_BINARY: &str = "version_agent/bin/linux-amd64/proxy-control-version-agent";

/// The reproducible builder of the host binaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    pub image: String,
    pub target: String,
    pub rustc: String,
}

/// `ReleaseIdentity` read from a tree (plus the 4.0 keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIdentity {
    pub tag: String,
    pub commit: String,
    pub manifest_sha256: String,
    pub components: BTreeMap<String, String>,
    pub artifacts: BTreeMap<String, String>,
    /// `version` (written by every builder; `None` only for a hand-made file).
    pub version: Option<String>,
    /// Tree path → sha256 of each prebuilt binary; empty before 4.0.
    pub binaries: BTreeMap<String, String>,
    pub builder: Option<Builder>,
}

/// Why a tree's identity could not be used (`CliError` texts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// `this tree carries no release identity; install from a built release`.
    Missing,
    /// `the release identity is incomplete`.
    Incomplete,
    /// A malformed 4.0 key: `the release identity binaries are invalid` /
    /// `the release identity builder is invalid`.
    Invalid(&'static str),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Missing => {
                f.write_str("this tree carries no release identity; install from a built release")
            }
            IdentityError::Incomplete => f.write_str("the release identity is incomplete"),
            IdentityError::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for IdentityError {}

/// `str(value)` for a JSON scalar (`True`, `None`, Python float repr); `None` for a container,
/// whose Python `repr` nobody should be trusting as an identity field.
pub fn py_str(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Bool(true) => Some("True".into()),
        Value::Bool(false) => Some("False".into()),
        Value::Null => Some("None".into()),
        Value::Number(number) => Some(match (number.as_i64(), number.as_u64(), number.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => crate::json::float_repr(f),
            _ => return None,
        }),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn string_map(value: Option<&Value>) -> Result<BTreeMap<String, String>, IdentityError> {
    match value {
        None => Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(key, value)| py_str(value).map(|v| (key.clone(), v)).ok_or(IdentityError::Incomplete))
            .collect(),
        Some(_) => Err(IdentityError::Incomplete),
    }
}

impl ReleaseIdentity {
    /// Parses `release.json` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<ReleaseIdentity, IdentityError> {
        let document = loads(data).map_err(|_| IdentityError::Missing)?;
        let Value::Object(map) = document else {
            return Err(IdentityError::Incomplete);
        };
        let field = |key: &str| map.get(key).and_then(py_str).ok_or(IdentityError::Incomplete);
        Ok(ReleaseIdentity {
            tag: field("tag")?,
            commit: field("commit")?,
            manifest_sha256: field("manifest_sha256")?,
            components: string_map(map.get("components"))?,
            artifacts: string_map(map.get("artifacts"))?,
            version: map.get("version").and_then(Value::as_str).map(str::to_string),
            binaries: binaries(map.get("binaries"))?,
            builder: builder(&map)?,
        })
    }

    /// `release_identity(source_dir)`: `<source_dir>/release/release.json`.
    pub fn read(source_dir: &Path) -> Result<ReleaseIdentity, IdentityError> {
        let data = fs::read(source_dir.join(IDENTITY_PATH)).map_err(|_| IdentityError::Missing)?;
        ReleaseIdentity::from_bytes(&data)
    }
}

fn binaries(value: Option<&Value>) -> Result<BTreeMap<String, String>, IdentityError> {
    const INVALID: IdentityError = IdentityError::Invalid("the release identity binaries are invalid");
    let Some(value) = value else { return Ok(BTreeMap::new()) };
    let map = value.as_object().ok_or(INVALID)?;
    let mut out = BTreeMap::new();
    for (path, digest) in map {
        let digest = digest.as_str().ok_or(INVALID)?;
        if normalize_archive_path(path).ok().as_deref() != Some(path.as_str()) || !is_sha256(digest) {
            return Err(INVALID);
        }
        out.insert(path.clone(), digest.to_string());
    }
    Ok(out)
}

fn builder(map: &Map<String, Value>) -> Result<Option<Builder>, IdentityError> {
    const INVALID: IdentityError = IdentityError::Invalid("the release identity builder is invalid");
    let Some(value) = map.get("builder") else { return Ok(None) };
    let builder = value.as_object().ok_or(INVALID)?;
    let text = |key: &str| {
        builder.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string).ok_or(INVALID)
    };
    Ok(Some(Builder { image: text("image")?, target: text("target")?, rustc: text("rustc")? }))
}

/// Checks every `binaries` entry of a tree after extraction (host inventory §9.3): a regular
/// file (not a symlink) with mode `0755` and the recorded sha256. The message names the path.
pub fn verify_binaries(tree: &Path, identity: &ReleaseIdentity) -> Result<(), String> {
    for (path, expected) in &identity.binaries {
        let full = tree.join(path);
        let metadata = fs::symlink_metadata(&full).map_err(|_| format!("release binary is missing: {path}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!("release binary is not a regular file: {path}"));
        }
        if metadata.permissions().mode() & 0o7777 != 0o755 {
            return Err(format!("release binary mode is not 0755: {path}"));
        }
        let actual = crate::fs::sha256_file(&full).map_err(|_| format!("release binary is unreadable: {path}"))?;
        if !crate::constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(format!("release binary digest mismatch: {path}"));
        }
    }
    Ok(())
}

/// The published `release-manifest.json` asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedManifest {
    pub archive: String,
    pub archive_sha256: String,
    pub commit: String,
    pub external_manifest_sha256: String,
    pub file_count: u64,
    pub schema: i64,
    pub source_epoch: i64,
    pub tag: String,
    pub version: String,
}

impl PublishedManifest {
    /// Parses the asset; every field of `release/build.py` is required with its type.
    pub fn from_bytes(data: &[u8]) -> Result<PublishedManifest, String> {
        let document = loads(data).map_err(|_| "the release manifest is unreadable".to_string())?;
        let map = document.as_object().ok_or("the release manifest is not an object")?;
        let text = |key: &str| {
            map.get(key).and_then(Value::as_str).map(str::to_string).ok_or(format!("the release manifest lacks {key}"))
        };
        let integer =
            |key: &str| map.get(key).and_then(Value::as_i64).ok_or(format!("the release manifest lacks {key}"));
        Ok(PublishedManifest {
            archive: text("archive")?,
            archive_sha256: text("archive_sha256")?,
            commit: text("commit")?,
            external_manifest_sha256: text("external_manifest_sha256")?,
            file_count: integer("file_count")?.max(0) as u64,
            schema: integer("schema")?,
            source_epoch: integer("source_epoch")?,
            tag: text("tag")?,
            version: text("version")?,
        })
    }

    /// `install-release.sh`'s `check_manifest`: the manifest describes exactly this archive of
    /// this release.
    pub fn describes(&self, archive_name: &str, archive_sha256: &str, version: &str) -> Result<(), &'static str> {
        if self.archive != archive_name {
            return Err("the manifest names a different archive");
        }
        if self.archive_sha256 != archive_sha256 {
            return Err("the manifest records a different archive digest");
        }
        if self.version != version || self.tag != format!("v{version}") {
            return Err("the manifest version or tag disagrees with the requested release");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod tests;
