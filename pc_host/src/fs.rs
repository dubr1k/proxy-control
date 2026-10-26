//! Durable file operations and rooted host paths (`installer/transaction.py:77-184`,
//! `:1550-1592`).
//!
//! Every helper mirrors the Python one it replaces, including the fsync points the journal's
//! crash safety rests on. One deliberate difference: [`atomic_write`] creates its temporary
//! file `O_EXCL` with mode `0600` before writing, where Python created it with the umask mode
//! and narrowed it only after the data was written (DIFFERENCES.md, host WP1).

use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::TxError;
use crate::pytext::py_path_str;

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Lowercase hex SHA-256 of what `reader` yields, read in 1 MiB chunks.
pub fn sha256_reader(reader: &mut dyn Read) -> io::Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

/// Lowercase hex SHA-256 of a file's content (follows symlinks, like `Path.read_bytes`).
pub fn sha256_file(path: &Path) -> io::Result<String> {
    sha256_reader(&mut File::open(path)?)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// `uuid.uuid4().hex`: 32 lowercase hex digits with the version and variant bits of a UUID 4.
pub fn uuid4_hex() -> String {
    let mut bytes = random_bytes::<16>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    hex(&bytes)
}

/// `secrets.token_hex(n)` for a compile-time `N`.
pub fn token_hex<const N: usize>() -> String {
    hex(&random_bytes::<N>())
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("the kernel random source is available");
    bytes
}

/// `Path.parent`: `/` for `/`, `.` for a bare name.
pub fn py_parent(path: &Path) -> PathBuf {
    match path.parent() {
        None => {
            if path.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                path.to_path_buf()
            }
        }
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// `fsync_directory`: open the directory read-only and fsync it.
pub fn fsync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(path)?.sync_all()
}

/// `fsync_file`: open read-only and fsync.
pub fn fsync_file(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// `fsync_tree`: persist a copied tree bottom-up (regular files, then subdirectories, then the
/// directory itself; symlinks are skipped and never followed), then fsync the tree's parent.
/// Unreadable directories are skipped, as `os.walk` skips them.
pub fn fsync_tree(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        fsync_tree_inner(path)?;
    }
    fsync_directory(&py_parent(path))
}

fn fsync_tree_inner(directory: &Path) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(());
    };
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            directories.push(path);
        } else if kind.is_file() {
            files.push(path);
        }
    }
    for child in &directories {
        fsync_tree_inner(child)?;
    }
    for file in &files {
        fsync_file(file)?;
    }
    for child in &directories {
        fsync_directory(child)?;
    }
    fsync_directory(directory)
}

/// `ensure_parent`: create the missing ancestors of `path` (umask mode) and fsync each new
/// directory's parent; `ENOTDIR` when the nearest existing ancestor is not a directory.
pub fn ensure_parent(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = py_parent(path);
    while !cursor.exists() {
        let next = py_parent(&cursor);
        missing.push(cursor);
        cursor = next;
    }
    if !cursor.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    for directory in missing.iter().rev() {
        fs::create_dir(directory)?;
        fsync_directory(&py_parent(directory))?;
    }
    Ok(())
}

/// `durable_mkdir`: create `path` and its missing ancestors; only `path` itself gets `mode`
/// (narrowed by the umask), each new directory and its parent are fsynced. An existing
/// directory is left as it is.
pub fn durable_mkdir(path: &Path, mode: u32) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    while !cursor.exists() {
        let next = py_parent(&cursor);
        missing.push(cursor);
        cursor = next;
    }
    if !cursor.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    for directory in missing.iter().rev() {
        let mut builder = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, if directory == path { mode } else { 0o777 });
        builder.create(directory)?;
        fsync_directory(directory)?;
        fsync_directory(&py_parent(directory))?;
    }
    Ok(())
}

/// `atomic_write`: replace `path` with `data`, ending with exactly `mode` (and `owner` when
/// given). Order: missing parents → temporary `.<name>.<uuid4hex>.tmp` in the same directory,
/// created `O_EXCL|O_NOFOLLOW` with mode `0600` → write → `fchmod(mode)` → `fchown` → `fsync` →
/// `rename` → fsync the directory. The temporary file is removed on any failure.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> io::Result<()> {
    ensure_parent(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{} has an empty name", path.display())))?;
    let mut temporary_name = Vec::from(&b"."[..]);
    temporary_name.extend_from_slice(name.as_bytes());
    temporary_name.extend_from_slice(format!(".{}.tmp", uuid4_hex()).as_bytes());
    let temporary = path.with_file_name(OsStr::from_bytes(&temporary_name));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(data)?;
        file.flush()?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid)) = owner {
            // SAFETY: the descriptor is owned by `file` and valid for the call.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        fsync_directory(&py_parent(path))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// `durable_copy2`: `shutil.copy2` (content, then atime/mtime in nanoseconds, extended
/// attributes and the permission bits; into `destination/<name>` when `destination` is a
/// directory), then fsync the copy and its directory.
pub fn durable_copy2(source: &Path, destination: &Path) -> io::Result<()> {
    ensure_parent(destination)?;
    let mut target = destination.to_path_buf();
    if destination.is_dir() {
        if let Some(name) = source.file_name() {
            target = destination.join(name);
        }
    }
    if let (Ok(a), Ok(b)) = (fs::metadata(source), fs::metadata(&target)) {
        if a.dev() == b.dev() && a.ino() == b.ino() {
            return Err(io::Error::other(format!(
                "{} and {} are the same file",
                crate::pytext::py_repr(&py_path_str(source)),
                crate::pytext::py_repr(&py_path_str(&target))
            )));
        }
    }
    let mut input = File::open(source)?;
    let metadata = input.metadata()?;
    let mut output = File::create(&target)?;
    io::copy(&mut input, &mut output)?;
    let times = [
        libc::timespec { tv_sec: metadata.atime() as _, tv_nsec: metadata.atime_nsec() as _ },
        libc::timespec { tv_sec: metadata.mtime() as _, tv_nsec: metadata.mtime_nsec() as _ },
    ];
    // SAFETY: valid descriptor and a two-element timespec array.
    if unsafe { libc::futimens(output.as_raw_fd(), times.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    copy_xattrs(&input, &output)?;
    output.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    drop(output);
    fsync_file(destination)?;
    fsync_directory(&py_parent(destination))
}

#[cfg(target_os = "linux")]
fn copy_xattrs(source: &File, destination: &File) -> io::Result<()> {
    let ignored =
        |err: &io::Error| matches!(err.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::ENODATA) | Some(libc::EINVAL));
    let mut names = vec![0u8; 4096];
    let length = loop {
        // SAFETY: valid descriptor and buffer.
        let n = unsafe { libc::flistxattr(source.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
        if n >= 0 {
            break n as usize;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ERANGE) {
            names.resize(names.len() * 4, 0);
            continue;
        }
        return if ignored(&err) { Ok(()) } else { Err(err) };
    };
    for name in names[..length].split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let name = CString::new(name).expect("split at NUL");
        let mut value = vec![0u8; 4096];
        let size = loop {
            // SAFETY: valid descriptor, NUL-terminated name and buffer.
            let n =
                unsafe { libc::fgetxattr(source.as_raw_fd(), name.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
            if n >= 0 {
                break Some(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                value.resize(value.len() * 4, 0);
                continue;
            }
            if ignored(&err) {
                break None;
            }
            return Err(err);
        };
        let Some(size) = size else { continue };
        // SAFETY: valid descriptor, name and value buffer of `size` bytes.
        let rc = unsafe { libc::fsetxattr(destination.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), size, 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if !(ignored(&err) || err.raw_os_error() == Some(libc::EPERM)) {
                return Err(err);
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn copy_xattrs(_source: &File, _destination: &File) -> io::Result<()> {
    Ok(())
}

/// `durable_symlink`: create the missing parents, the symlink, fsync its directory.
pub fn durable_symlink(target: &str, path: &Path) -> io::Result<()> {
    ensure_parent(path)?;
    std::os::unix::fs::symlink(target, path)?;
    fsync_directory(&py_parent(path))
}

/// `durable_remove`: remove a file, symlink or whole tree (never following symlinks), then fsync
/// the parent. A missing path is an error unless `missing_ok`.
pub fn durable_remove(path: &Path, missing_ok: bool) -> io::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        if missing_ok {
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    fsync_directory(&py_parent(path))
}

/// `_root_path`: `absolute` (which must start with `/` and have no `..`) placed under `root`,
/// with the nearest existing ancestor of its parent resolved inside `root`.
///
/// Errors: `TransactionError("host paths must be absolute and normalized")`,
/// `OwnershipError("supplied root is not a safe directory")`,
/// `OwnershipError("rooted path escapes supplied root")`.
pub fn root_path(root: &Path, absolute: &str) -> Result<PathBuf, TxError> {
    let pure = Path::new(absolute);
    if !absolute.starts_with('/') || pure.components().any(|c| c == Component::ParentDir) {
        return Err(TxError::transaction("host paths must be absolute and normalized"));
    }
    let mut candidate = if root.as_os_str().is_empty() { PathBuf::from(".") } else { root.to_path_buf() };
    for component in pure.components() {
        if let Component::Normal(name) = component {
            candidate.push(name);
        }
    }
    assert_contained(root, &py_parent(&candidate))?;
    Ok(candidate)
}

/// `_assert_contained`: the nearest existing ancestor of `path` (a dangling symlink counts as
/// existing and then fails to resolve) must resolve inside `root`.
pub fn assert_contained(root: &Path, path: &Path) -> Result<(), TxError> {
    let root = if root.as_os_str().is_empty() { Path::new(".") } else { root };
    let boundary = fs::canonicalize(root).map_err(|_| TxError::ownership("supplied root is not a safe directory"))?;
    let mut cursor = path.to_path_buf();
    while !cursor.exists() && !is_symlink(&cursor) {
        let parent = py_parent(&cursor);
        if parent == cursor {
            return Err(TxError::ownership("rooted path escapes supplied root"));
        }
        cursor = parent;
    }
    match fs::canonicalize(&cursor) {
        Ok(resolved) if resolved.starts_with(&boundary) => Ok(()),
        _ => Err(TxError::ownership("rooted path escapes supplied root")),
    }
}

/// `_owned_path`: the journal key of a declared host path (`/` + its parts, so `/a//b/./c` is
/// `/a/b/c`) and where it lives under `root`. `OwnershipError("owned path is unsafe")` for a
/// relative path or one with `..`.
///
/// Python's `PurePosixPath` keeps a leading `//` as its own anchor, so `//a` becomes the key
/// `////a`; that quirk is kept so journals compare equal.
pub fn owned_path(root: &Path, raw: &str) -> Result<(String, PathBuf), TxError> {
    if !raw.starts_with('/') {
        return Err(TxError::ownership("owned path is unsafe"));
    }
    let parts: Vec<&str> = raw.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if parts.contains(&"..") {
        return Err(TxError::ownership("owned path is unsafe"));
    }
    let double_anchor = raw.starts_with("//") && !raw.starts_with("///");
    let normalized = if double_anchor {
        let mut all = vec!["//"];
        all.extend(parts);
        format!("/{}", all.join("/"))
    } else {
        format!("/{}", parts.join("/"))
    };
    let rooted = root_path(root, &normalized)?;
    Ok((normalized, rooted))
}

/// What a journal records about an owned path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    File,
    Symlink,
}

impl PathKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathKind::File => "file",
            PathKind::Symlink => "symlink",
        }
    }
}

/// `_path_identity`: a symlink is `sha256("symlink:" + target)`, a regular file (or a path
/// resolving to one) the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathIdentity {
    pub kind: PathKind,
    pub sha256: String,
}

impl PathIdentity {
    /// `{"kind": …, "sha256": …}` as the journal stores it.
    pub fn to_json(&self) -> Value {
        json!({"kind": self.kind.as_str(), "sha256": self.sha256})
    }
}

/// `_path_identity(path)`; `OwnershipError("owned file is missing: <path>")` when it is neither a
/// symlink nor a regular file.
pub fn path_identity(path: &Path) -> Result<PathIdentity, TxError> {
    if is_symlink(path) {
        let target = fs::read_link(path)?;
        let mut data = Vec::from(&b"symlink:"[..]);
        data.extend_from_slice(target.as_os_str().as_bytes());
        return Ok(PathIdentity { kind: PathKind::Symlink, sha256: sha256_hex(&data) });
    }
    if !path.is_file() {
        return Err(TxError::ownership(format!("owned file is missing: {}", py_path_str(path))));
    }
    Ok(PathIdentity { kind: PathKind::File, sha256: sha256_file(path)? })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn sha_and_uuid() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let id = uuid4_hex();
        assert_eq!(id.len(), 32);
        assert_eq!(&id[12..13], "4");
        assert!("89ab".contains(&id[16..17]));
        assert_eq!(token_hex::<16>().len(), 32);
    }

    #[test]
    fn py_parent_matches_pathlib() {
        assert_eq!(py_parent(Path::new("/")), PathBuf::from("/"));
        assert_eq!(py_parent(Path::new("/a")), PathBuf::from("/"));
        assert_eq!(py_parent(Path::new("a")), PathBuf::from("."));
        assert_eq!(py_parent(Path::new("a/b")), PathBuf::from("a"));
    }

    #[test]
    fn atomic_write_creates_parents_and_exact_mode() {
        let dir = TempDir::new("atomic");
        let path = dir.path().join("deep/er/state.json");
        atomic_write(&path, b"one", 0o600, None).unwrap();
        atomic_write(&path, b"two", 0o640, None).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o640);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state.json")]);
        // The final mode even when wider than the creation mode, and with an explicit owner.
        let me = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        atomic_write(&path, b"three", 0o644, Some(me)).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o644);
    }

    #[test]
    fn atomic_write_replaces_a_symlink_instead_of_writing_through_it() {
        let dir = TempDir::new("atomic-link");
        let outside = dir.path().join("outside");
        fs::write(&outside, b"keep").unwrap();
        let path = dir.path().join("state.json");
        symlink(&outside, &path).unwrap();
        atomic_write(&path, b"new", 0o600, None).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"keep");
        assert!(!fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn atomic_write_leaves_no_temporary_on_failure() {
        let dir = TempDir::new("atomic-fail");
        let blocker = dir.path().join("file");
        fs::write(&blocker, b"x").unwrap();
        let err = atomic_write(&blocker.join("child"), b"x", 0o600, None).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR));
        // A directory in the way of the rename: the temporary file is removed again.
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside"), b"x").unwrap();
        assert!(atomic_write(&target, b"x", 0o600, None).is_err());
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn ensure_parent_and_durable_mkdir() {
        let dir = TempDir::new("mkdir");
        ensure_parent(&dir.path().join("a/b/c")).unwrap();
        assert!(dir.path().join("a/b").is_dir());
        assert!(!dir.path().join("a/b/c").exists());
        durable_mkdir(&dir.path().join("x/y"), 0o700).unwrap();
        assert_eq!(fs::metadata(dir.path().join("x/y")).unwrap().permissions().mode() & 0o777, 0o700);
        durable_mkdir(&dir.path().join("x/y"), 0o755).unwrap();
        assert_eq!(fs::metadata(dir.path().join("x/y")).unwrap().permissions().mode() & 0o777, 0o700);
        fs::write(dir.path().join("f"), b"").unwrap();
        assert_eq!(durable_mkdir(&dir.path().join("f/g"), 0o700).unwrap_err().raw_os_error(), Some(libc::ENOTDIR));
        assert_eq!(ensure_parent(&dir.path().join("f/g/h")).unwrap_err().raw_os_error(), Some(libc::ENOTDIR));
    }

    #[test]
    fn copy_symlink_remove_and_tree_sync() {
        let dir = TempDir::new("copy");
        let source = dir.path().join("src");
        fs::write(&source, b"payload").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o751)).unwrap();
        let copy = dir.path().join("out/copy");
        durable_copy2(&source, &copy).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"payload");
        let (a, b) = (fs::metadata(&source).unwrap(), fs::metadata(&copy).unwrap());
        assert_eq!(b.mode() & 0o7777, 0o751);
        assert_eq!((a.mtime(), a.mtime_nsec()), (b.mtime(), b.mtime_nsec()));
        assert!(durable_copy2(&source, &source).unwrap_err().to_string().contains("are the same file"));

        durable_symlink("copy", &dir.path().join("out/link")).unwrap();
        assert_eq!(fs::read_link(dir.path().join("out/link")).unwrap(), PathBuf::from("copy"));
        fsync_tree(&dir.path().join("out")).unwrap();
        fsync_tree(&dir.path().join("missing")).unwrap();

        durable_remove(&dir.path().join("out/link"), false).unwrap();
        assert!(copy.exists());
        durable_remove(&dir.path().join("out"), false).unwrap();
        assert!(!dir.path().join("out").exists());
        assert_eq!(durable_remove(&dir.path().join("out"), false).unwrap_err().raw_os_error(), Some(libc::ENOENT));
        durable_remove(&dir.path().join("out"), true).unwrap();
    }

    #[test]
    fn root_path_contains_paths() {
        let dir = TempDir::new("root");
        let root = dir.path();
        assert_eq!(root_path(root, "/etc/x").unwrap(), root.join("etc/x"));
        assert_eq!(root_path(root, "//etc/./y/").unwrap(), root.join("etc/y"));
        for bad in ["etc/x", "/etc/../x", ""] {
            let err = root_path(root, bad).unwrap_err();
            assert!(matches!(err, TxError::Transaction(_)));
            assert_eq!(err.to_string(), "host paths must be absolute and normalized");
        }
        // An ancestor that is a symlink out of the root.
        let outside = TempDir::new("root-outside");
        symlink(outside.path(), root.join("escape")).unwrap();
        let err = root_path(root, "/escape/file").unwrap_err();
        assert_eq!(err.to_string(), "rooted path escapes supplied root");
        assert_eq!(err.python_class_name(), "OwnershipError");
        // A dangling symlink as the nearest ancestor does not resolve.
        symlink(root.join("nowhere"), root.join("dangling")).unwrap();
        assert_eq!(root_path(root, "/dangling/a/b").unwrap_err().to_string(), "rooted path escapes supplied root");
        // A symlink inside the root is fine.
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("inner")).unwrap();
        assert!(root_path(root, "/inner/file").is_ok());
        let err = root_path(&root.join("absent"), "/x").unwrap_err();
        assert_eq!(err.to_string(), "supplied root is not a safe directory");
        // `/` is the root itself; its parent lies outside.
        assert_eq!(root_path(root, "/").unwrap_err().to_string(), "rooted path escapes supplied root");
    }

    #[test]
    fn owned_path_normalises_like_pathlib() {
        let dir = TempDir::new("owned");
        let root = dir.path();
        assert_eq!(owned_path(root, "/a//b/./c").unwrap(), ("/a/b/c".to_string(), root.join("a/b/c")));
        assert_eq!(owned_path(root, "///a").unwrap().0, "/a");
        assert_eq!(owned_path(root, "//a").unwrap().0, "////a");
        for bad in ["a/b", "/a/../b", ""] {
            assert_eq!(owned_path(root, bad).unwrap_err().to_string(), "owned path is unsafe");
        }
    }

    #[test]
    fn path_identity_hashes_files_and_symlinks() {
        let dir = TempDir::new("identity");
        let file = dir.path().join("f");
        fs::write(&file, b"abc").unwrap();
        let identity = path_identity(&file).unwrap();
        assert_eq!(identity.kind, PathKind::File);
        assert_eq!(identity.sha256, sha256_hex(b"abc"));
        assert_eq!(identity.to_json(), json!({"kind": "file", "sha256": sha256_hex(b"abc")}));
        let link = dir.path().join("l");
        symlink("target/x", &link).unwrap();
        let identity = path_identity(&link).unwrap();
        assert_eq!(identity.kind, PathKind::Symlink);
        assert_eq!(identity.sha256, sha256_hex(b"symlink:target/x"));
        let err = path_identity(&dir.path().join("missing")).unwrap_err();
        assert_eq!(err.to_string(), format!("owned file is missing: {}", dir.path().join("missing").display()));
        assert!(path_identity(dir.path()).is_err());
    }
}
