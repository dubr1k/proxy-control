//! Shared host boundary for the three service adapters (not a second runner contract).
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pc_host::runner::{Capture, RunOptions};
use serde_json::{json, Map, Value};

use super::AdapterContext;
use crate::error::Error;
use crate::journal::CheckpointData;
use crate::planner::Action;

#[derive(Clone)]
pub(super) struct Host {
    pub context: AdapterContext,
    pub class: &'static str,
    pub label: &'static str,
}
impl Host {
    pub fn new(context: &AdapterContext, class: &'static str, label: &'static str) -> Self {
        Self { context: context.clone(), class, label }
    }
    pub fn error(&self, message: impl AsRef<str>) -> Error {
        Error::other(self.class, message.as_ref())
    }
    pub fn path(&self, absolute: &str) -> Result<PathBuf, Error> {
        let path = pc_host::fs::root_path(&self.context.root, absolute)?;
        let mut cursor = self.context.root.clone();
        for part in Path::new(absolute).components().skip(1) {
            cursor.push(part);
            if fs::symlink_metadata(&cursor).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(self.error(format!("{} path crosses a symlink", self.label)));
            }
        }
        Ok(path)
    }
    pub fn write(&self, absolute: &str, bytes: &[u8], mode: u32) -> Result<(), Error> {
        let path = self.path(absolute)?;
        let owner = (self.context.root == Path::new("/") && unsafe { libc::geteuid() } == 0).then_some((0, 0));
        pc_host::fs::atomic_write(&path, bytes, mode, owner)?;
        Ok(())
    }
    pub fn text(&self, absolute: &str) -> Result<String, Error> {
        Ok(fs::read_to_string(self.path(absolute)?)?)
    }
    pub fn remove(&self, absolute: &str) -> Result<(), Error> {
        pc_host::fs::durable_remove(&self.path(absolute)?, true)?;
        Ok(())
    }
    pub fn digest(&self, absolute: &str) -> Result<String, Error> {
        Ok(pc_host::fs::sha256_file(&self.path(absolute)?)?)
    }
    pub fn capture(&self, argv: &[&str], max_chars: usize, limits: Capture) -> String {
        self.context.runner.capture(argv, max_chars, limits)
    }
    pub fn run(&self, argv: &[&str]) -> Result<(), Error> {
        let result = self.context.runner.run(argv, &RunOptions::default())?;
        if result.returncode != 0 {
            // Arguments and stderr can carry API keys: neither belongs in journal errors.
            return Err(self.error(format!("{} command failed: {}", self.label, argv.first().unwrap_or(&"command"))));
        }
        Ok(())
    }
    pub fn prepare(&self, action: &Action, marker: &str, foreign: &[&str]) -> Result<CheckpointData, Error> {
        let path = self.path(marker)?;
        let (adoption, nonce) = if path.exists() {
            let text = fs::read_to_string(path)?.trim().to_owned();
            if !hex(&text, 32) {
                return Err(self.error(format!("{} ownership marker is invalid", self.label)));
            }
            ("recovery", text)
        } else {
            for name in foreign {
                if self.path(name)?.exists() {
                    return Err(
                        self.error(format!("foreign {} installation ({name}) requires explicit migration", self.label))
                    );
                }
            }
            ("absent", pc_host::fs::token_hex::<16>())
        };
        Ok(json!({"owner":action.owner,"adoption":adoption,"marker_value":nonce,"ownership":{}})
            .as_object()
            .unwrap()
            .clone())
    }
    pub fn checkpoint(&self, action: &Action, data: &CheckpointData) -> Result<(), Error> {
        let keys: BTreeSet<_> = data.keys().map(String::as_str).collect();
        if keys != BTreeSet::from(["owner", "adoption", "marker_value", "ownership"])
            || data.get("owner").and_then(Value::as_str) != Some(&action.owner)
            || !matches!(data.get("adoption").and_then(Value::as_str), Some("absent" | "recovery"))
            || !data.get("marker_value").and_then(Value::as_str).is_some_and(|v| hex(v, 32))
            || !data.get("ownership").is_some_and(Value::is_object)
        {
            return Err(self.error(format!("{} checkpoint is invalid", self.label)));
        }
        Ok(())
    }
    pub fn marker(&self, marker: &str, data: &CheckpointData, missing_ok: bool) -> Result<(), Error> {
        let path = self.path(marker)?;
        if !path.exists() {
            if missing_ok {
                return Ok(());
            }
            return Err(self.error(format!("{} ownership marker is missing", self.label)));
        }
        if fs::read_to_string(path)?.trim() != data["marker_value"].as_str().unwrap() {
            return Err(self.error(format!("{} ownership marker drifted", self.label)));
        }
        Ok(())
    }
    pub fn claim(&self, marker: &str, data: &CheckpointData) -> Result<(), Error> {
        self.marker(marker, data, true)?;
        self.write(marker, format!("{}\n", data["marker_value"].as_str().unwrap()).as_bytes(), 0o600)
    }
    pub fn ownership(&self, files: &[&str]) -> Result<Map<String, Value>, Error> {
        files.iter().map(|p| Ok(((*p).into(), json!(self.digest(p)?)))).collect()
    }
    pub fn own_secret(&self, absolute: &str) -> Result<(), Error> {
        let path = self.path(absolute)?;
        let info = fs::metadata(&path)?;
        if !info.is_file() || info.mode() & 0o007 != 0 {
            return Err(self.error("MCP secret file is unsafe or world-readable"));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440))?;
        if self.context.root == Path::new("/") && unsafe { libc::geteuid() } == 0 {
            let file = fs::File::open(&path)?;
            use std::os::fd::AsRawFd;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 10007) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
}

pub(super) fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(super) fn mutations(
    action: &Action,
    name: &str,
    owner: &str,
    keys: &[&str],
    class: &'static str,
) -> Result<BTreeMap<String, String>, Error> {
    let invalid = || {
        Error::other(
            class,
            match name {
                "warp" => "invalid WARP action",
                "mcp" => "MCP action is invalid",
                "version_agent" => "version-agent action is invalid",
                _ => "service action is invalid",
            },
        )
    };
    if action.id != format!("{name}.runtime") || action.adapter != name || action.owner != owner {
        return Err(invalid());
    }
    let mut values = BTreeMap::new();
    for item in &action.mutations {
        let (key, value) = item.split_once('=').ok_or_else(invalid)?;
        if values.insert(key.into(), value.into()).is_some() {
            return Err(invalid());
        }
    }
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys.iter().copied().collect() {
        return Err(invalid());
    }
    Ok(values)
}
pub(super) fn compose_files(value: &str) -> Option<Vec<&str>> {
    let files: Vec<_> = value.split(':').collect();
    if files.first() != Some(&"compose.yaml")
        || files.iter().collect::<BTreeSet<_>>().len() != files.len()
        || files.iter().any(|f| {
            *f != "compose.yaml"
                && !f
                    .strip_prefix("compose.")
                    .and_then(|name| name.strip_suffix(".yaml"))
                    .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        })
    {
        return None;
    }
    Some(files)
}
pub(super) fn env_key(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.starts_with('#') {
        None
    } else {
        line.split_once('=').map(|(k, _)| k.trim())
    }
}
pub(super) fn env_values(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some(key) = env_key(line) {
            out.entry(key.into()).or_insert_with(|| line.trim().split_once('=').unwrap().1.into());
        }
    }
    out
}
/// A release/installed tree contains regular files and directories only. Never follow a link.
pub(super) fn tree_files(root: &Path) -> Result<BTreeMap<String, PathBuf>, Error> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<(), Error> {
        let info = fs::symlink_metadata(path)?;
        if info.file_type().is_symlink() {
            return Err(Error::other("VersionAgentError", "version-agent code directory contains a symlink"));
        }
        if info.is_dir() {
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), out)?;
            }
        } else if info.is_file() {
            out.insert(path.strip_prefix(root).unwrap().to_string_lossy().into_owned(), path.into());
        } else {
            return Err(Error::other("VersionAgentError", "version-agent code directory contains an unsafe file"));
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut out)?;
    }
    Ok(out)
}
