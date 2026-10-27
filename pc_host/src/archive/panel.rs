//! The native panel release archive: the bounded sync allow-list and the checks before
//! extracting any archive member.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::safe::{tar_members, TarMember};
use crate::pytext::py_repr;

/// Every member of a release archive sits under this directory.
pub const PANEL_ARCHIVE_PREFIX: &str = "proxy-control";

/// The release tree entries a panel update syncs into the project directory
/// (`/opt/mtproxy-shared443/<entry>`). It is also the **only** allow-list of the ownership
/// handoff: a name outside it is "panel sync scope is unsafe". Everything else in the project
/// directory (`secrets/`, `.env*`, `version-overrides/`, certificates) is never touched, and an
/// entry absent from an archive is left as it is.
///
/// Preserve the installer's native trees and the host crates needed for manager builds.
/// Fleet v1 overlays are intentionally absent: the native version-agent refuses installed
/// legacy units, overlays and Compose containers before changing the panel's files or database.
pub const PANEL_SYNC: &[&str] = &[
    "panel",
    "installer",
    "scripts",
    "docker",
    "mieru_manager",
    "naive_manager",
    "xray_router_manager",
    "awg_manager",
    "trusttunnel_manager",
    "pc_common",
    "pc_host",
    "installer_core",
    "mcp_server",
    "release",
    "docs",
    "compose.yaml",
    "compose.naive.yaml",
    "compose.mieru.yaml",
    "compose.xray-router.yaml",
    "compose.amneziawg.yaml",
    "compose.trusttunnel.yaml",
    "compose.mcp.yaml",
    "VERSION",
    "uninstall.sh",
    "install.sh",
    "install-bootstrap",
    "CHANGELOG.md",
    "CHANGELOG.ru.md",
    "README.md",
    "README.en.md",
    "THIRD_PARTY_NOTICES.md",
    "LICENSE",
];

/// The managers written in Rust; their images build `pc_common`, so a change there rebuilds them.
pub const RUST_MANAGERS: &[&str] =
    &["trusttunnel_manager", "awg_manager", "mieru_manager", "mcp_server", "naive_manager", "xray_router_manager"];
/// The crate the Rust managers share.
pub const RUST_SHARED: &str = "pc_common";
/// The agent's own tree, synced to `/opt/proxy-control/version_agent` (outside [`PANEL_SYNC`]).
pub const PANEL_AGENT_DIR: &str = "version_agent";
/// Host directory of the synced entries.
pub const PROJECT_DIR: &str = "/opt/mtproxy-shared443";
/// Host directory that holds [`PANEL_AGENT_DIR`].
pub const AGENT_ROOT: &str = "/opt/proxy-control";
/// The largest unpacked tree an update accepts (sum of member sizes).
pub const MAX_PANEL_TREE: u64 = 512 * 1024 * 1024;
/// Headers and padding allowed on top of [`MAX_PANEL_TREE`] when the archive is decompressed.
const DECOMPRESSED_SLACK: u64 = 64 * 1024 * 1024;

/// Whether the ownership handoff may rebase `name` (the allow-list is [`PANEL_SYNC`]).
pub fn handoff_allows(name: &str) -> bool {
    PANEL_SYNC.contains(&name)
}

/// `UpdateError` raised by the panel archive checks (the agent shows the text as is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelArchiveError(pub String);

impl std::fmt::Display for PanelArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PanelArchiveError {}

/// One member that passed the preflight (not the top-level `proxy-control` directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelMember {
    /// The member name, `proxy-control/…`.
    pub name: String,
    pub is_dir: bool,
    pub mode: u32,
    pub size: u64,
    data_offset: u64,
}

impl PanelMember {
    /// The path below the release root (`name` without `proxy-control/`).
    pub fn relative(&self) -> &str {
        &self.name[PANEL_ARCHIVE_PREFIX.len() + 1..]
    }
}

/// `_preflight_panel_archive`: every member under `proxy-control/`, a regular file or a
/// directory, no empty/`.`/`..` component, at most [`MAX_PANEL_TREE`] bytes in total, and a
/// `proxy-control/VERSION`.
pub(crate) fn preflight(members: &[TarMember]) -> Result<Vec<PanelMember>, PanelArchiveError> {
    let mut accepted = Vec::new();
    let mut total: u64 = 0;
    for member in members {
        let parts: Vec<&str> = member.name.split('/').collect();
        if member.name.starts_with('/')
            || parts[0] != PANEL_ARCHIVE_PREFIX
            || parts.iter().any(|part| matches!(*part, "" | "." | ".."))
        {
            return Err(PanelArchiveError(format!("panel archive: refusing member {}", py_repr(&member.name))));
        }
        if !(member.is_reg() || member.is_dir()) || member.kind_byte == b'S' {
            return Err(PanelArchiveError(format!(
                "panel archive: refusing non-regular member {}",
                py_repr(&member.name)
            )));
        }
        total += member.size;
        if total > MAX_PANEL_TREE {
            return Err(PanelArchiveError("panel archive: tree is too large".into()));
        }
        if parts.len() > 1 {
            accepted.push(PanelMember {
                name: member.name.clone(),
                is_dir: member.is_dir(),
                mode: member.mode,
                size: member.size,
                data_offset: member.data_offset,
            });
        }
    }
    if !accepted.iter().any(|m| m.name == format!("{PANEL_ARCHIVE_PREFIX}/VERSION")) {
        return Err(PanelArchiveError("panel archive: no VERSION file".into()));
    }
    Ok(accepted)
}

/// A release archive, decompressed into an anonymous file and preflighted.
pub struct PanelArchive {
    decoded: File,
    members: Vec<PanelMember>,
}

fn not_targz(detail: impl std::fmt::Display) -> PanelArchiveError {
    PanelArchiveError(format!("panel archive is not a tar.gz: {detail}"))
}

impl PanelArchive {
    /// Gunzips `payload` (bounded) and runs the preflight over every member.
    pub fn open(payload: &[u8]) -> Result<PanelArchive, PanelArchiveError> {
        if !payload.starts_with(b"\x1f\x8b") {
            return Err(not_targz("not a gzip file"));
        }
        let mut decoded = anonymous_file().map_err(not_targz)?;
        let limit = MAX_PANEL_TREE + DECOMPRESSED_SLACK;
        let mut decoder = flate2::read::MultiGzDecoder::new(payload).take(limit + 1);
        let copied = io::copy(&mut decoder, &mut decoded).map_err(not_targz)?;
        if copied > limit {
            return Err(PanelArchiveError("panel archive: tree is too large".into()));
        }
        let mut members = Vec::new();
        tar_members(&mut decoded, |member: &TarMember, _payload: &mut dyn Read| -> io::Result<()> {
            members.push(member.clone());
            Ok(())
        })
        .map_err(not_targz)?;
        let members = preflight(&members)?;
        Ok(PanelArchive { decoded, members })
    }

    /// The accepted members in archive order.
    pub fn members(&self) -> &[PanelMember] {
        &self.members
    }

    /// The bytes of one member.
    pub fn read(&mut self, member: &PanelMember) -> io::Result<Vec<u8>> {
        self.decoded.seek(SeekFrom::Start(member.data_offset))?;
        let mut data = Vec::with_capacity(member.size as usize);
        (&mut self.decoded).take(member.size).read_to_end(&mut data)?;
        if data.len() as u64 != member.size {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated member"));
        }
        Ok(data)
    }

    /// `_extract_panel_archive` after the preflight: `staging` must not exist; directories are
    /// created, files written and given `mode & 0o777` (or `0o644` when that is zero).
    pub fn extract_to(&mut self, staging: &Path) -> Result<(), PanelArchiveError> {
        let io_error = |err: io::Error| PanelArchiveError(format!("panel archive: {err}"));
        if staging.exists() || fs::symlink_metadata(staging).is_ok() {
            return Err(io_error(io::Error::from_raw_os_error(libc::EEXIST)));
        }
        fs::create_dir_all(staging).map_err(io_error)?;
        let members = self.members.clone();
        for member in &members {
            let target: PathBuf =
                member.relative().split('/').fold(staging.to_path_buf(), |path, part| path.join(part));
            if member.is_dir {
                fs::create_dir_all(&target).map_err(io_error)?;
                continue;
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(io_error)?;
            }
            let data = self.read(member).map_err(|_| {
                PanelArchiveError(format!("panel archive: unreadable member {}", py_repr(&member.name)))
            })?;
            let mut file = File::create(&target).map_err(io_error)?;
            file.write_all(&data).map_err(io_error)?;
            let mode = if member.mode & 0o777 == 0 { 0o644 } else { member.mode & 0o777 };
            fs::set_permissions(&target, fs::Permissions::from_mode(mode)).map_err(io_error)?;
        }
        Ok(())
    }
}

/// `VersionAgent._extract_panel_archive(payload, staging)`.
pub fn extract_panel_archive(payload: &[u8], staging: &Path) -> Result<(), PanelArchiveError> {
    PanelArchive::open(payload)?.extract_to(staging)
}

fn anonymous_file() -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!(".pc-host-panel-{}", crate::fs::token_hex::<16>()));
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    fs::remove_file(&path)?;
    Ok(file)
}

#[cfg(test)]
#[path = "panel_tests.rs"]
mod tests;
