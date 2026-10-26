//! Dirfd-anchored extraction of reviewed artifacts (`installer/release.py:227-422`,
//! `:519-565`, `:827-1473`): `safe_extract_tar` (3x-ui) and `safe_extract_zip` (Xray).
//!
//! Nothing in an archive is trusted. The tar extractor copies the archive into an anonymous
//! file while hashing it (so swapping or rewriting the path afterwards changes nothing),
//! decompresses into a second anonymous file under a bound, walks the raw 512-byte headers,
//! validates every entry against the manifest, and only then writes. Writes go through
//! descriptors anchored at `/`: every ancestor of the destination is opened `O_NOFOLLOW` and
//! must be owned by a trusted uid and not writable by others (unless sticky with a trusted
//! child). The tree is built in a private `.<name>.stage-<hex>` directory and swapped in by
//! `renameat`; the old tree is removed iteratively through descriptors.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::dirfd;
use super::release::{
    is_member_name, normalize_archive_path, open_regular_file, require_sha256, resolve_symlink_target, MemberPin,
    ReleaseError, Result, DEFAULT_MAX_MEMBER_SIZE,
};
use crate::pytext::{py_path_str, py_repr};

const COPY_CHUNK: usize = 1024 * 1024;
const TAR_BLOCK: u64 = 512;
pub const HARD_MAX_COMPRESSED_SIZE: u64 = 1024 * 1024 * 1024;
pub const HARD_MAX_DECOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024;
pub const HARD_MAX_METADATA_SIZE: u64 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_COMPRESSED_SIZE: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_METADATA_SIZE: u64 = 1024 * 1024;

/// One reviewed tar entry (`ArchiveEntry`). `kind` is `file`, `directory` or `symlink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub kind: String,
    pub mode: Option<u32>,
    pub sha256: Option<String>,
    pub link_target: Option<String>,
}

impl ArchiveEntry {
    pub fn file(path: &str, mode: Option<u32>, sha256: Option<&str>) -> Self {
        ArchiveEntry { path: path.into(), kind: "file".into(), mode, sha256: sha256.map(Into::into), link_target: None }
    }

    pub fn directory(path: &str, mode: Option<u32>) -> Self {
        ArchiveEntry { path: path.into(), kind: "directory".into(), mode, sha256: None, link_target: None }
    }

    pub fn symlink(path: &str, mode: Option<u32>, target: &str) -> Self {
        ArchiveEntry { path: path.into(), kind: "symlink".into(), mode, sha256: None, link_target: Some(target.into()) }
    }
}

/// `ArchiveManifest`: the exact layout and bounds a tar artifact must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveManifest {
    pub entries: Vec<ArchiveEntry>,
    pub archive_sha256: String,
    pub max_entries: u64,
    pub max_total_size: u64,
    pub max_compressed_size: u64,
    pub max_decompressed_size: u64,
    pub max_metadata_size: u64,
}

impl ArchiveManifest {
    /// The Python defaults: 10 000 entries, 1 GiB total, 512 MiB compressed, 1 GiB
    /// decompressed, 1 MiB of extension metadata.
    pub fn new(entries: Vec<ArchiveEntry>, archive_sha256: &str) -> Self {
        ArchiveManifest {
            entries,
            archive_sha256: archive_sha256.into(),
            max_entries: 10_000,
            max_total_size: 1024 * 1024 * 1024,
            max_compressed_size: DEFAULT_MAX_COMPRESSED_SIZE,
            max_decompressed_size: DEFAULT_MAX_DECOMPRESSED_SIZE,
            max_metadata_size: DEFAULT_MAX_METADATA_SIZE,
        }
    }
}

// ----------------------------------------------------------------------------------------------
// Test hooks: the Python tests monkeypatch private functions; the Rust tests inject failures at
// the same points.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hook {
    /// After the private copy was verified (Python `_copy_verified_archive`).
    AfterVerifiedCopy,
    /// After the destination was anchored (Python `_validate_destination`).
    AfterAnchor,
    /// Instead of copying a regular member (Python `_copy_regular_member`).
    CopyMember,
    /// Before removing a tree by descriptor (Python `_remove_tree_at`), with its name.
    RemoveTree,
}

#[cfg(test)]
pub(crate) mod hooks {
    use std::cell::RefCell;

    use super::Hook;

    pub(crate) type HookFn = Box<dyn FnMut(Hook, &str) -> Result<(), super::HookFailure>>;

    thread_local! {
        pub(crate) static HOOK: RefCell<Option<HookFn>> = const { RefCell::new(None) };
    }

    pub(crate) fn set(hook: impl FnMut(Hook, &str) -> Result<(), super::HookFailure> + 'static) {
        HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn clear() {
        HOOK.with(|cell| *cell.borrow_mut() = None);
    }
}

/// What an injected hook makes the code under test see.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum HookFailure {
    Io(io::Error),
    Release(ReleaseError),
    /// A non-`OSError` exception (Python `RuntimeError`).
    Other,
}

#[cfg(test)]
fn hook(point: Hook, name: &str) -> std::result::Result<(), HookFailure> {
    hooks::HOOK.with(|cell| match cell.borrow_mut().as_mut() {
        Some(hook) => hook(point, name),
        None => Ok(()),
    })
}

#[cfg(not(test))]
#[inline(always)]
fn hook(_point: Hook, _name: &str) -> std::result::Result<(), HookFailure> {
    Ok(())
}

// ----------------------------------------------------------------------------------------------

/// Internal failure: a `ReleaseError` passes through, an I/O or format error becomes "could not
/// validate/extract archive" depending on whether a stage exists.
enum Failure {
    Release(ReleaseError),
    Io(io::Error),
}

impl From<ReleaseError> for Failure {
    fn from(err: ReleaseError) -> Self {
        Failure::Release(err)
    }
}

impl From<io::Error> for Failure {
    fn from(err: io::Error) -> Self {
        Failure::Io(err)
    }
}

impl From<HookFailure> for Failure {
    fn from(err: HookFailure) -> Self {
        match err {
            HookFailure::Io(err) => Failure::Io(err),
            HookFailure::Release(err) => Failure::Release(err),
            HookFailure::Other => Failure::Io(io::Error::other("injected failure")),
        }
    }
}

type Step<T> = std::result::Result<T, Failure>;

/// An anonymous temporary file (`tempfile.TemporaryFile`).
fn anonymous_file() -> io::Result<File> {
    let directory = std::env::temp_dir();
    let path = directory.join(format!(".pc-host-{}", crate::fs::token_hex::<16>()));
    let file =
        std::fs::OpenOptions::new().read(true).write(true).create_new(true).custom_flags_nofollow().open(&path)?;
    std::fs::remove_file(&path)?;
    Ok(file)
}

trait NoFollow {
    fn custom_flags_nofollow(&mut self) -> &mut Self;
}

impl NoFollow for std::fs::OpenOptions {
    fn custom_flags_nofollow(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    }
}

fn read_chunk(source: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match source.read(buffer) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// `_copy_verified_archive`.
fn copy_verified_archive(
    source: &mut File,
    private: &mut File,
    expected: &str,
    archive: &Path,
    max_compressed_size: u64,
) -> Step<()> {
    let mut digest = Sha256::new();
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        let want = (COPY_CHUNK as u64).min(max_compressed_size - total + 1) as usize;
        let read = read_chunk(source, &mut buffer[..want])?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_compressed_size {
            return Err(ReleaseError(format!("compressed archive size limit exceeded: {max_compressed_size}")).into());
        }
        digest.update(&buffer[..read]);
        private.write_all(&buffer[..read])?;
    }
    let actual = crate::fs::hex(&digest.finalize());
    if !crate::constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        let name = archive.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        return Err(
            ReleaseError(format!("archive digest mismatch for {name}: expected {expected}, got {actual}")).into()
        );
    }
    private.flush()?;
    private.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// `_decode_bounded_tar`: gunzip (bzip2 and xz refused) or copy a plain tar, bounded.
fn decode_bounded_tar(raw: &mut File, decoded: &mut File, max_decompressed_size: u64) -> Step<()> {
    raw.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 6];
    let mut have = 0;
    while have < magic.len() {
        let read = read_chunk(raw, &mut magic[have..])?;
        if read == 0 {
            break;
        }
        have += read;
    }
    raw.seek(SeekFrom::Start(0))?;
    let magic = &magic[..have];
    let mut source: Box<dyn Read + '_> = if magic.starts_with(b"\x1f\x8b") {
        Box::new(flate2::read::MultiGzDecoder::new(&mut *raw))
    } else if magic.starts_with(b"BZh") || magic.starts_with(b"\xfd7zXZ\x00") {
        return Err(ReleaseError::new("unsupported archive compression; use gzip or tar").into());
    } else {
        Box::new(&mut *raw)
    };
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        let want = (COPY_CHUNK as u64).min(max_decompressed_size - total + 1) as usize;
        let read = read_chunk(&mut source, &mut buffer[..want])?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_decompressed_size {
            return Err(
                ReleaseError(format!("decompressed archive size limit exceeded: {max_decompressed_size}")).into()
            );
        }
        decoded.write_all(&buffer[..read])?;
    }
    decoded.flush()?;
    decoded.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// Tar extension types (pax `x`/`g`, Solaris `X`, GNU long name `L` / long link `K`).
const EXTENSION_TYPES: &[u8] = b"xgXLK";

/// `_scan_tar_records`: walk the raw headers before `tarfile` sees them — sizes in plain octal
/// only, extension metadata bounded, no payload on non-regular entries, a zero block required.
pub(crate) fn scan_tar_records(source: &mut File, max_metadata_size: u64) -> Result<()> {
    let io_error = |_| ReleaseError::new("truncated tar header");
    let size = source.seek(SeekFrom::End(0)).map_err(io_error)?;
    source.seek(SeekFrom::Start(0)).map_err(io_error)?;
    let mut offset: u64 = 0;
    let mut metadata: u64 = 0;
    let mut header = [0u8; TAR_BLOCK as usize];
    while offset + TAR_BLOCK <= size {
        source.read_exact(&mut header).map_err(io_error)?;
        if header.iter().all(|b| *b == 0) {
            source.seek(SeekFrom::Start(0)).map_err(io_error)?;
            return Ok(());
        }
        let payload = parse_tar_size(&header[124..136])?;
        let kind = header[156];
        if EXTENSION_TYPES.contains(&kind) {
            metadata += payload;
            if metadata > max_metadata_size {
                return Err(ReleaseError(format!("tar metadata limit exceeded: {max_metadata_size}")));
            }
        } else if kind != b'0' && kind != 0 && payload != 0 {
            return Err(ReleaseError::new("payload-bearing non-regular tar entry"));
        }
        let padded = payload.div_ceil(TAR_BLOCK) * TAR_BLOCK;
        offset += TAR_BLOCK + padded;
        if offset > size {
            return Err(ReleaseError::new("tar entry exceeds decompressed archive"));
        }
        source.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    }
    Err(ReleaseError::new("tar archive is missing a zero terminator"))
}

/// `_parse_tar_size`: plain octal (NUL/space padded); base-256 refused.
fn parse_tar_size(field: &[u8]) -> Result<u64> {
    if field[0] & 0x80 != 0 {
        return Err(ReleaseError::new("unsupported tar numeric encoding"));
    }
    let end = field.iter().rposition(|b| *b != 0 && *b != b' ').map(|i| i + 1).unwrap_or(0);
    let start = field[..end].iter().position(|b| *b != b' ').unwrap_or(end);
    let value = &field[start..end];
    if value.is_empty() {
        return Ok(0);
    }
    if !value.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return Err(ReleaseError::new("invalid tar size field"));
    }
    u64::from_str_radix(std::str::from_utf8(value).expect("octal digits"), 8)
        .map_err(|_| ReleaseError::new("invalid tar size field"))
}

/// A member as Python's `tarfile` would present it.
#[derive(Debug, Clone)]
pub(crate) struct TarMember {
    /// `TarInfo.name` (directories without their trailing slash).
    pub name: String,
    /// The raw type byte after tarfile's `AREGTYPE` + trailing slash → directory rule.
    pub kind_byte: u8,
    pub mode: u32,
    pub size: u64,
    pub linkname: String,
    /// Offset of the payload in the decoded tar.
    pub data_offset: u64,
}

impl TarMember {
    pub fn is_dir(&self) -> bool {
        self.kind_byte == b'5'
    }

    /// `isreg()`: `0`, `\0`, contiguous `7` and GNU sparse `S`.
    pub fn is_reg(&self) -> bool {
        matches!(self.kind_byte, b'0' | 0 | b'7' | b'S')
    }
}

/// Reads every member of a decoded tar the way `tarfile` lists them (extension headers folded
/// in, pax global headers skipped), handing each to `visit` with a reader of its payload.
/// Format errors are I/O errors.
pub(crate) fn tar_members<E: From<io::Error>>(
    source: &mut File,
    mut visit: impl FnMut(&TarMember, &mut dyn Read) -> std::result::Result<(), E>,
) -> std::result::Result<(), E> {
    source.seek(SeekFrom::Start(0))?;
    let mut archive = tar::Archive::new(&mut *source);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let header = entry.header();
        let raw_kind = header.as_bytes()[156];
        if raw_kind == b'g' {
            continue;
        }
        let path = entry.path_bytes();
        let name = std::str::from_utf8(&path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "member name is not UTF-8"))?
            .to_string();
        let mut kind_byte = raw_kind;
        if kind_byte == 0 && name.ends_with('/') {
            kind_byte = b'5';
        }
        let name = if kind_byte == b'5' { name.trim_end_matches('/').to_string() } else { name };
        let linkname = match entry.link_name_bytes() {
            Some(link) => std::str::from_utf8(&link)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "link name is not UTF-8"))?
                .to_string(),
            None => String::new(),
        };
        let header_size = header.entry_size()?;
        if entry.size() != header_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "pax size override").into());
        }
        let member = TarMember {
            name,
            kind_byte,
            mode: header.mode()?,
            size: entry.size(),
            linkname,
            data_offset: entry.raw_file_position(),
        };
        visit(&member, &mut entry)?;
    }
    Ok(())
}

fn member_reader<'a>(source: &'a mut File, member: &TarMember) -> io::Result<io::Take<&'a mut File>> {
    source.seek(SeekFrom::Start(member.data_offset))?;
    Ok(Read::take(source, member.size))
}

#[derive(Debug, Clone)]
struct Validated {
    path: String,
    kind: &'static str,
    member: TarMember,
    expected: ArchiveEntry,
    resolved_link_target: Option<String>,
}

/// `_validate_archive_manifest`.
fn validate_archive_manifest(manifest: &ArchiveManifest) -> Result<BTreeMap<String, ArchiveEntry>> {
    require_sha256(&manifest.archive_sha256, "archive")?;
    if !(1..=HARD_MAX_COMPRESSED_SIZE).contains(&manifest.max_compressed_size) {
        return Err(ReleaseError::new("archive max_compressed_size must be within the hard safety bound"));
    }
    if !(1..=HARD_MAX_DECOMPRESSED_SIZE).contains(&manifest.max_decompressed_size) {
        return Err(ReleaseError::new("archive max_decompressed_size must be within the hard safety bound"));
    }
    if manifest.max_metadata_size > HARD_MAX_METADATA_SIZE {
        return Err(ReleaseError::new("archive max_metadata_size must be within the hard safety bound"));
    }
    if manifest.max_entries == 0 {
        return Err(ReleaseError::new("archive max_entries must be a positive integer"));
    }
    if manifest.entries.is_empty() {
        return Err(ReleaseError::new("archive manifest entries must be a non-empty tuple"));
    }
    let mut expected = BTreeMap::new();
    for entry in &manifest.entries {
        let normalized = normalize_archive_path(&entry.path)?;
        if normalized != entry.path {
            return Err(ReleaseError(format!("archive manifest path must be canonical: {}", entry.path)));
        }
        if expected.contains_key(&normalized) {
            return Err(ReleaseError(format!("duplicate archive manifest path: {normalized}")));
        }
        if !matches!(entry.kind.as_str(), "file" | "directory" | "symlink") {
            return Err(ReleaseError(format!("invalid archive manifest entry kind: {}", entry.kind)));
        }
        if entry.mode.is_some_and(|mode| mode > 0o777) {
            return Err(ReleaseError(format!("invalid archive manifest mode: {}", entry.path)));
        }
        if let Some(sha) = &entry.sha256 {
            if entry.kind != "file" {
                return Err(ReleaseError::new("only regular files may have a member SHA-256"));
            }
            require_sha256(sha, &format!("archive member {}", entry.path))?;
        }
        if entry.kind == "symlink" {
            let Some(target) = &entry.link_target else {
                return Err(ReleaseError(format!("symlink manifest entry requires a target: {}", entry.path)));
            };
            resolve_symlink_target(&entry.path, target)?;
        } else if entry.link_target.is_some() {
            return Err(ReleaseError(format!("non-symlink manifest entry has a target: {}", entry.path)));
        }
        expected.insert(normalized, entry.clone());
    }
    Ok(expected)
}

/// `_tar_member_kind`.
fn tar_member_kind(member: &TarMember) -> Result<&'static str> {
    if member.is_reg() && member.kind_byte != b'S' {
        return Ok("file");
    }
    if member.is_dir() {
        return Ok("directory");
    }
    if member.kind_byte == b'2' {
        return Ok("symlink");
    }
    Err(ReleaseError(format!("unsupported archive entry type: {}", member.name)))
}

fn hex_digest_of(reader: &mut dyn Read) -> io::Result<String> {
    crate::fs::sha256_reader(reader)
}

/// `_validate_tar`.
fn validate_tar(
    decoded: &mut File,
    manifest: &ArchiveManifest,
    expected: &BTreeMap<String, ArchiveEntry>,
) -> Step<Vec<Validated>> {
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();
    let mut validated: Vec<Validated> = Vec::new();
    let mut total_size: u64 = 0;
    let mut count: u64 = 0;
    tar_members(decoded, |member: &TarMember, payload: &mut dyn Read| -> Step<()> {
        count += 1;
        if count > manifest.max_entries {
            return Err(ReleaseError(format!("archive entry count limit exceeded: {}", manifest.max_entries)).into());
        }
        let path = normalize_archive_path(&member.name)?;
        if actual.contains_key(&path) {
            return Err(ReleaseError(format!("duplicate normalized archive path: {path}")).into());
        }
        let kind = tar_member_kind(member)?;
        if member.mode & 0o6000 != 0 {
            return Err(ReleaseError(format!("archive entry has setuid or setgid mode: {path}")).into());
        }
        if kind != "file" && member.size != 0 {
            return Err(ReleaseError(format!("payload-bearing non-regular tar entry: {path}")).into());
        }
        if kind == "file" {
            total_size += member.size;
            if total_size > manifest.max_total_size {
                return Err(ReleaseError(format!("archive size limit exceeded: {}", manifest.max_total_size)).into());
            }
        }
        let Some(expected_entry) = expected.get(&path) else {
            return Err(ReleaseError(format!("unexpected archive entry: {path}")).into());
        };
        if kind != expected_entry.kind {
            return Err(ReleaseError(format!(
                "archive entry type mismatch for {path}: expected {}, got {kind}",
                expected_entry.kind
            ))
            .into());
        }
        let actual_mode = member.mode & 0o777;
        if let Some(mode) = expected_entry.mode {
            if actual_mode != mode {
                return Err(ReleaseError(format!(
                    "archive entry mode mismatch for {path}: expected {mode:o}, got {actual_mode:o}"
                ))
                .into());
            }
        }
        let mut resolved_link_target = None;
        if kind == "symlink" {
            resolved_link_target = Some(resolve_symlink_target(&path, &member.linkname)?);
            if Some(&member.linkname) != expected_entry.link_target.as_ref() {
                return Err(ReleaseError(format!("archive symlink target mismatch for {path}")).into());
            }
        } else if let Some(sha) = &expected_entry.sha256 {
            let digest = hex_digest_of(payload)?;
            if !crate::constant_time_eq(digest.as_bytes(), sha.as_bytes()) {
                return Err(ReleaseError(format!("archive member digest mismatch: {}", member.name)).into());
            }
        }
        actual.insert(path.clone(), validated.len());
        validated.push(Validated {
            path,
            kind,
            member: member.clone(),
            expected: expected_entry.clone(),
            resolved_link_target,
        });
        Ok(())
    })?;
    if let Some(missing) = expected.keys().find(|path| !actual.contains_key(*path)) {
        return Err(ReleaseError(format!("missing archive entry: {missing}")).into());
    }
    for item in &validated {
        let mut parts: Vec<&str> = item.path.split('/').collect();
        parts.pop();
        while !parts.is_empty() {
            let parent = parts.join("/");
            if let Some(index) = actual.get(&parent) {
                if validated[*index].kind != "directory" {
                    return Err(ReleaseError(format!("archive path has a non-directory parent: {}", item.path)).into());
                }
            }
            parts.pop();
        }
    }
    for item in &validated {
        if let Some(target) = &item.resolved_link_target {
            if !actual.contains_key(target) {
                return Err(
                    ReleaseError(format!("archive symlink target is not an internal entry: {}", item.path)).into()
                );
            }
        }
    }
    Ok(validated)
}

// ----------------------------------------------------------------------------------------------
// The destination anchor.

struct Anchor {
    destination_name: Vec<u8>,
    components: Vec<Vec<u8>>,
    descriptors: Vec<OwnedFd>,
    identities: Vec<(u64, u64, u32, u32)>,
    destination_identity: Option<(u64, u64)>,
}

impl Anchor {
    fn parent_fd(&self) -> RawFd {
        self.descriptors.last().expect("the anchor has a root").as_raw_fd()
    }
}

fn fingerprint(stat: &libc::stat) -> (u64, u64, u32, u32) {
    (stat.st_dev, stat.st_ino, stat.st_uid, stat.st_mode & 0o7777)
}

fn trusted_uids() -> BTreeSet<u32> {
    // SAFETY: plain getters.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    [0, uid, euid].into_iter().collect()
}

/// `Path(destination).absolute()` split into the parent's components and the final name.
fn absolute_components(destination: &Path) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let absolute = if destination.is_absolute() {
        destination.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| ReleaseError::new("destination path is invalid"))?.join(destination)
    };
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Normal(name) => parts.push(name.as_bytes().to_vec()),
            std::path::Component::ParentDir => parts.push(b"..".to_vec()),
            _ => {}
        }
    }
    let Some(name) = parts.pop() else {
        return Err(ReleaseError::new("destination path is invalid"));
    };
    if name.is_empty() || name == b"." || name == b".." {
        return Err(ReleaseError::new("destination path is invalid"));
    }
    Ok((parts, name))
}

/// `_validate_destination`.
fn validate_destination(destination: &Path) -> Step<Anchor> {
    let (components, destination_name) = absolute_components(destination)?;
    let root = dirfd::open_path(b"/")?;
    let root_stat = dirfd::fstat(root.as_raw_fd())?;
    let mut descriptors = vec![root];
    let mut identities = vec![fingerprint(&root_stat)];
    let mut chain = vec![root_stat];
    for component in &components {
        let parent = descriptors.last().expect("root").as_raw_fd();
        let before = dirfd::stat_at(parent, component)?;
        let shown = String::from_utf8_lossy(component);
        if dirfd::is_symlink(&before) {
            return Err(ReleaseError(format!("destination parent is a symlink: {shown}")).into());
        }
        if !dirfd::is_dir(&before) {
            return Err(ReleaseError(format!("destination parent is not a directory: {shown}")).into());
        }
        let child = dirfd::open_dir_at(parent, component)?;
        let after = dirfd::fstat(child.as_raw_fd())?;
        if dirfd::identity(&before) != dirfd::identity(&after) {
            return Err(ReleaseError::new("destination parent changed during validation").into());
        }
        descriptors.push(child);
        identities.push(fingerprint(&after));
        chain.push(after);
    }
    enforce_destination_chain_trust(&chain)?;
    let destination_identity = destination_identity(descriptors.last().expect("root").as_raw_fd(), &destination_name)?;
    Ok(Anchor { destination_name, components, descriptors, identities, destination_identity })
}

/// `_enforce_destination_chain_trust`.
fn enforce_destination_chain_trust(chain: &[libc::stat]) -> Result<()> {
    let trusted = trusted_uids();
    let immediate_parent = chain.len() - 1;
    for (index, stat) in chain.iter().enumerate() {
        if !trusted.contains(&stat.st_uid) {
            return Err(ReleaseError::new("untrusted destination ancestor owner"));
        }
        if stat.st_mode & 0o022 == 0 {
            continue;
        }
        if index == immediate_parent {
            return Err(ReleaseError::new("untrusted destination parent permissions"));
        }
        if stat.st_mode & libc::S_ISVTX == 0 {
            return Err(ReleaseError::new("untrusted destination ancestor permissions"));
        }
        if !trusted.contains(&chain[index + 1].st_uid) {
            return Err(ReleaseError::new("untrusted entry below sticky destination ancestor"));
        }
    }
    Ok(())
}

/// `_destination_identity`: absent, or a trusted directory that is not a symlink.
fn destination_identity(parent: RawFd, name: &[u8]) -> Step<Option<(u64, u64)>> {
    let stat = match dirfd::stat_at(parent, name) {
        Ok(stat) => stat,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if dirfd::is_symlink(&stat) {
        return Err(ReleaseError::new("destination must not be a symlink").into());
    }
    if !dirfd::is_dir(&stat) {
        return Err(ReleaseError::new("destination must be a directory or absent").into());
    }
    if !trusted_uids().contains(&stat.st_uid) {
        return Err(ReleaseError::new("untrusted destination owner").into());
    }
    Ok(Some(dirfd::identity(&stat)))
}

/// `_revalidate_destination`: nothing on the anchored chain moved since validation.
fn revalidate_destination(anchor: &Anchor) -> Result<()> {
    let check = || -> Step<Option<(u64, u64)>> {
        if fingerprint(&dirfd::fstat(anchor.descriptors[0].as_raw_fd())?) != anchor.identities[0] {
            return Err(ReleaseError::new("destination root changed before mutation").into());
        }
        for (index, component) in anchor.components.iter().enumerate() {
            let stat = dirfd::stat_at(anchor.descriptors[index].as_raw_fd(), component)?;
            if !dirfd::is_dir(&stat) || fingerprint(&stat) != anchor.identities[index + 1] {
                return Err(ReleaseError::new("destination parent changed before mutation").into());
            }
        }
        destination_identity(anchor.parent_fd(), &anchor.destination_name)
    };
    let current = match check() {
        Ok(current) => current,
        Err(Failure::Release(err)) => return Err(err),
        Err(Failure::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
            return Err(ReleaseError::new("destination parent changed before mutation"))
        }
        Err(Failure::Io(_)) => return Err(ReleaseError::new("could not revalidate destination parent")),
    };
    if current != anchor.destination_identity {
        return Err(ReleaseError::new("destination changed before mutation"));
    }
    Ok(())
}

/// `_reserve_directory_name`: `mkdirat(prefix + token_hex(16), 0700)`, 32 attempts.
fn reserve_directory_name(parent: RawFd, prefix: &[u8]) -> Step<Vec<u8>> {
    for _ in 0..32 {
        let mut name = prefix.to_vec();
        name.extend_from_slice(crate::fs::token_hex::<16>().as_bytes());
        match dirfd::mkdir_at(parent, &name, 0o700) {
            Ok(()) => return Ok(name),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Err(ReleaseError::new("could not reserve a private destination entry").into())
}

fn prefixed(prefix: &str, name: &[u8], suffix: &str) -> Vec<u8> {
    let mut out = prefix.as_bytes().to_vec();
    out.extend_from_slice(name);
    out.extend_from_slice(suffix.as_bytes());
    out
}

/// `_create_private_stage`.
fn create_private_stage(anchor: &Anchor) -> Step<(Vec<u8>, OwnedFd)> {
    let name = reserve_directory_name(anchor.parent_fd(), &prefixed(".", &anchor.destination_name, ".stage-"))?;
    match dirfd::open_dir_at(anchor.parent_fd(), &name) {
        Ok(fd) => Ok((name, fd)),
        Err(err) => {
            best_effort_remove_tree_at(anchor.parent_fd(), &name);
            Err(err.into())
        }
    }
}

/// `_open_or_create_directory`: walk `parts` below `root`, creating missing directories (0700)
/// and refusing anything that is not a directory.
fn open_or_create_directory(root: RawFd, parts: &[&str]) -> Step<OwnedFd> {
    let mut current = dirfd::dup(root)?;
    for component in parts {
        let name = component.as_bytes();
        match dirfd::mkdir_at(current.as_raw_fd(), name, 0o700) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
        let stat = dirfd::stat_at(current.as_raw_fd(), name)?;
        if !dirfd::is_dir(&stat) {
            return Err(ReleaseError(format!("archive parent is not a directory: {component}")).into());
        }
        let child = dirfd::open_dir_at(current.as_raw_fd(), name)?;
        if dirfd::identity(&stat) != dirfd::identity(&dirfd::fstat(child.as_raw_fd())?) {
            return Err(ReleaseError::new("archive directory changed while extracting").into());
        }
        current = child;
    }
    Ok(current)
}

/// `_copy_regular_member`.
fn copy_regular_member(
    decoded: &mut File,
    member: &TarMember,
    parent: RawFd,
    name: &str,
    expected: Option<&str>,
) -> Step<()> {
    hook(Hook::CopyMember, &member.name)?;
    let mut output = dirfd::create_file_at(parent, name.as_bytes(), 0o600)?;
    let mut source = member_reader(decoded, member)?;
    let mut digest = expected.map(|_| Sha256::new());
    let mut copied: u64 = 0;
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        let read = read_chunk(&mut source, &mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        copied += read as u64;
        if let Some(digest) = digest.as_mut() {
            digest.update(&buffer[..read]);
        }
    }
    if copied != member.size {
        return Err(ReleaseError(format!("archive member size changed while extracting: {}", member.name)).into());
    }
    if let (Some(digest), Some(expected)) = (digest, expected) {
        if !crate::constant_time_eq(crate::fs::hex(&digest.finalize()).as_bytes(), expected.as_bytes()) {
            return Err(ReleaseError(format!("archive member changed while extracting: {}", member.name)).into());
        }
    }
    dirfd::fchmod(output.as_raw_fd(), member.mode & 0o777)?;
    output.flush()?;
    dirfd::fsync(output.as_raw_fd())?;
    Ok(())
}

/// `_extract_members`: directories (shallow first) → files → symlinks → directory modes
/// (deepest first) → fsync the stage.
fn extract_members(decoded: &mut File, members: &[Validated], stage: RawFd) -> Step<()> {
    let split = |path: &str| path.split('/').map(str::to_string).collect::<Vec<_>>();
    let mut directories: Vec<&Validated> = members.iter().filter(|m| m.kind == "directory").collect();
    directories.sort_by(|a, b| (a.path.split('/').count(), &a.path).cmp(&(b.path.split('/').count(), &b.path)));
    let mut files: Vec<&Validated> = members.iter().filter(|m| m.kind == "file").collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut symlinks: Vec<&Validated> = members.iter().filter(|m| m.kind == "symlink").collect();
    symlinks.sort_by(|a, b| a.path.cmp(&b.path));

    for member in &directories {
        let parts = split(&member.path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        drop(open_or_create_directory(stage, &refs)?);
    }
    for member in &files {
        let parts = split(&member.path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (name, parents) = refs.split_last().expect("non-empty path");
        let parent = open_or_create_directory(stage, parents)?;
        copy_regular_member(decoded, &member.member, parent.as_raw_fd(), name, member.expected.sha256.as_deref())?;
    }
    for member in &symlinks {
        let parts = split(&member.path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (name, parents) = refs.split_last().expect("non-empty path");
        let parent = open_or_create_directory(stage, parents)?;
        dirfd::symlink_at(member.member.linkname.as_bytes(), parent.as_raw_fd(), name.as_bytes())?;
    }
    for member in directories.iter().rev() {
        let parts = split(&member.path);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let fd = open_or_create_directory(stage, &refs)?;
        dirfd::fchmod(fd.as_raw_fd(), member.member.mode & 0o777)?;
    }
    dirfd::fsync(stage)?;
    Ok(())
}

/// `_replace_destination`: rename the stage in; an existing tree goes to `.<name>.backup-<hex>`
/// first and is removed afterwards (a failed removal is left behind, never reported).
fn replace_destination(anchor: &Anchor, stage_name: &[u8]) -> Step<()> {
    revalidate_destination(anchor)?;
    let parent = anchor.parent_fd();
    let destination = &anchor.destination_name;
    if anchor.destination_identity.is_none() {
        dirfd::rename_at(parent, stage_name, destination)?;
        return Ok(());
    }
    let backup = reserve_directory_name(parent, &prefixed(".", destination, ".backup-"))?;
    if let Err(err) = dirfd::rename_at(parent, destination, &backup) {
        best_effort_remove_tree_at(parent, &backup);
        return Err(err.into());
    }
    if let Err(replacement) = dirfd::rename_at(parent, stage_name, destination) {
        if dirfd::rename_at(parent, &backup, destination).is_err() {
            return Err(ReleaseError::new("destination replacement and rollback both failed").into());
        }
        return Err(replacement.into());
    }
    let _ = remove_tree_at(parent, &backup);
    Ok(())
}

/// `_remove_tree_at`: iterative, descriptor-based removal (no recursion, no path walking).
fn remove_tree_at(parent: RawFd, name: &[u8]) -> std::result::Result<(), HookFailure> {
    hook(Hook::RemoveTree, &String::from_utf8_lossy(name))?;
    let stat = match dirfd::stat_at(parent, name) {
        Ok(stat) => stat,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(HookFailure::Io(err)),
    };
    if !dirfd::is_dir(&stat) {
        return dirfd::unlink_at(parent, name, false).map_err(HookFailure::Io);
    }
    let io = HookFailure::Io;
    let top = dirfd::open_dir_at(parent, name).map_err(io)?;
    if dirfd::identity(&stat) != dirfd::identity(&dirfd::fstat(top.as_raw_fd()).map_err(HookFailure::Io)?) {
        return Err(HookFailure::Io(io::Error::other("directory changed during cleanup")));
    }
    // (parent descriptor, name, own descriptor, remaining names)
    struct Node {
        parent: Option<usize>,
        name: Vec<u8>,
        fd: OwnedFd,
        pending: Vec<Vec<u8>>,
    }
    let pending = dirfd::list(top.as_raw_fd()).map_err(HookFailure::Io)?;
    let mut stack = vec![Node { parent: None, name: name.to_vec(), fd: top, pending }];
    while let Some(node) = stack.last_mut() {
        let Some(child) = node.pending.pop() else {
            let node = stack.pop().expect("non-empty stack");
            let parent_fd = match node.parent {
                Some(index) => stack[index].fd.as_raw_fd(),
                None => parent,
            };
            drop(node.fd);
            dirfd::unlink_at(parent_fd, &node.name, true).map_err(HookFailure::Io)?;
            continue;
        };
        let node_fd = node.fd.as_raw_fd();
        let child_stat = dirfd::stat_at(node_fd, &child).map_err(HookFailure::Io)?;
        if !dirfd::is_dir(&child_stat) {
            dirfd::unlink_at(node_fd, &child, false).map_err(HookFailure::Io)?;
            continue;
        }
        let child_fd = dirfd::open_dir_at(node_fd, &child).map_err(HookFailure::Io)?;
        if dirfd::identity(&child_stat)
            != dirfd::identity(&dirfd::fstat(child_fd.as_raw_fd()).map_err(HookFailure::Io)?)
        {
            return Err(HookFailure::Io(io::Error::other("directory changed during cleanup")));
        }
        let pending = dirfd::list(child_fd.as_raw_fd()).map_err(HookFailure::Io)?;
        let parent_index = stack.len() - 1;
        stack.push(Node { parent: Some(parent_index), name: child, fd: child_fd, pending });
    }
    Ok(())
}

fn best_effort_remove_tree_at(parent: RawFd, name: &[u8]) {
    let _ = remove_tree_at(parent, name);
}

/// What the cleanup of a failed extraction needs.
struct Stage {
    name: Vec<u8>,
}

fn finish(archive: &Path, anchor: Option<&Anchor>, stage: Option<Stage>, result: Step<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(failure) => {
            let staged = match (anchor, stage) {
                (Some(anchor), Some(stage)) => {
                    best_effort_remove_tree_at(anchor.parent_fd(), &stage.name);
                    true
                }
                _ => false,
            };
            match failure {
                Failure::Release(err) => Err(err),
                Failure::Io(_) if staged => {
                    Err(ReleaseError(format!("could not extract archive: {}", py_path_str(archive))))
                }
                Failure::Io(_) => Err(ReleaseError(format!("could not validate archive: {}", py_path_str(archive)))),
            }
        }
    }
}

/// `safe_extract_tar(archive, destination, manifest)`: verify the copied bytes, then install
/// exactly the manifest's tree at `destination` through the anchored stage swap. Any failure
/// leaves a previous tree untouched and no stage behind.
pub fn safe_extract_tar(archive: &Path, destination: &Path, manifest: &ArchiveManifest) -> Result<()> {
    let expected = validate_archive_manifest(manifest)?;
    let mut source = open_regular_file(archive, "archive")?;
    let mut anchor: Option<Anchor> = None;
    let mut stage: Option<Stage> = None;
    let result = (|| -> Step<()> {
        let mut raw = anonymous_file()?;
        copy_verified_archive(&mut source, &mut raw, &manifest.archive_sha256, archive, manifest.max_compressed_size)?;
        hook(Hook::AfterVerifiedCopy, "")?;
        let mut decoded = anonymous_file()?;
        decode_bounded_tar(&mut raw, &mut decoded, manifest.max_decompressed_size)?;
        drop(raw);
        scan_tar_records(&mut decoded, manifest.max_metadata_size)?;
        let members = validate_tar(&mut decoded, manifest, &expected)?;
        anchor = Some(validate_destination(destination)?);
        hook(Hook::AfterAnchor, "")?;
        let anchored = anchor.as_ref().expect("just set");
        revalidate_destination(anchored)?;
        let (name, stage_fd) = create_private_stage(anchored)?;
        stage = Some(Stage { name });
        extract_members(&mut decoded, &members, stage_fd.as_raw_fd())?;
        drop(stage_fd);
        replace_destination(anchored, &stage.as_ref().expect("stage").name)?;
        stage = None;
        Ok(())
    })();
    finish(archive, anchor.as_ref(), stage, result)
}

/// `safe_extract_zip(archive, destination, members, max_member_bytes)`: write exactly the
/// reviewed members (plain names), their sizes counted while streaming and their digests
/// checked, through the same stage swap (stage mode 0755).
pub fn safe_extract_zip(
    archive: &Path,
    destination: &Path,
    members: &[(String, MemberPin)],
    max_member_bytes: u64,
) -> Result<()> {
    if members.is_empty() {
        return Err(ReleaseError::new("zip extraction needs at least one reviewed member"));
    }
    for (name, pin) in members {
        if !is_member_name(name) || name == "." || name == ".." {
            return Err(ReleaseError(format!("zip member name is not a plain file name: {}", py_repr(name))));
        }
        require_sha256(&pin.sha256, &format!("zip member {name}"))?;
        if !(1..=max_member_bytes).contains(&pin.size) {
            return Err(ReleaseError(format!("zip member size is out of bounds: {name}")));
        }
        if pin.mode & !0o777 != 0 {
            return Err(ReleaseError(format!("zip member mode is invalid: {name}")));
        }
    }
    let source = open_regular_file(archive, "archive")?;
    let mut anchor: Option<Anchor> = None;
    let mut stage: Option<Stage> = None;
    let result = (|| -> Step<()> {
        let mut bundle = zip::ZipArchive::new(source).map_err(zip_error)?;
        let mut indices = Vec::new();
        for (name, pin) in members {
            let Some(index) = bundle.index_for_name(name) else {
                return Err(ReleaseError(format!("archive lacks the reviewed member: {name}")).into());
            };
            let file = bundle.by_index_raw(index).map_err(zip_error)?;
            let link = (file.external_attributes() >> 16) & libc::S_IFMT == libc::S_IFLNK;
            if file.is_dir() || link || file.name().ok().as_deref() != Some(name.as_str()) {
                return Err(ReleaseError(format!("archive member is not a regular file: {name}")).into());
            }
            if file.size() != pin.size {
                return Err(ReleaseError(format!("archive member size differs from the reviewed size: {name}")).into());
            }
            indices.push(index);
        }
        anchor = Some(validate_destination(destination)?);
        hook(Hook::AfterAnchor, "")?;
        let anchored = anchor.as_ref().expect("just set");
        revalidate_destination(anchored)?;
        let (stage_name, stage_fd) = create_private_stage(anchored)?;
        stage = Some(Stage { name: stage_name });
        for ((name, pin), index) in members.iter().zip(indices) {
            let mut file = bundle.by_index(index).map_err(zip_error)?;
            copy_zip_member(&mut file, stage_fd.as_raw_fd(), name, pin)?;
        }
        dirfd::fchmod(stage_fd.as_raw_fd(), 0o755)?;
        dirfd::fsync(stage_fd.as_raw_fd())?;
        drop(stage_fd);
        replace_destination(anchored, &stage.as_ref().expect("stage").name)?;
        stage = None;
        Ok(())
    })();
    finish(archive, anchor.as_ref(), stage, result)
}

/// [`safe_extract_zip`] with the default 64 MiB member bound.
pub fn safe_extract_zip_default(archive: &Path, destination: &Path, members: &[(String, MemberPin)]) -> Result<()> {
    safe_extract_zip(archive, destination, members, DEFAULT_MAX_MEMBER_SIZE)
}

#[cfg(test)]
#[path = "safe_tests.rs"]
mod tests;

fn zip_error(err: zip::result::ZipError) -> Failure {
    Failure::Io(io::Error::other(err.to_string()))
}

/// `_copy_zip_member`.
fn copy_zip_member(source: &mut dyn Read, parent: RawFd, name: &str, pin: &MemberPin) -> Step<()> {
    let mut output = dirfd::create_file_at(parent, name.as_bytes(), 0o600)?;
    let mut digest = Sha256::new();
    let mut copied: u64 = 0;
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        let read = read_chunk(source, &mut buffer)?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        if copied > pin.size {
            return Err(ReleaseError(format!("archive member size changed while extracting: {name}")).into());
        }
        digest.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    if copied != pin.size {
        return Err(ReleaseError(format!("archive member size changed while extracting: {name}")).into());
    }
    if !crate::constant_time_eq(crate::fs::hex(&digest.finalize()).as_bytes(), pin.sha256.as_bytes()) {
        return Err(ReleaseError(format!("archive member digest mismatch: {name}")).into());
    }
    dirfd::fchmod(output.as_raw_fd(), pin.mode)?;
    output.flush()?;
    dirfd::fsync(output.as_raw_fd())?;
    Ok(())
}
