//! Validate and fd-stage the immutable Compose Mieru token secret (`panel/stage_secret.py`).
//!
//! Run by the image entrypoint as root, before privileges are dropped, when Mieru is enabled:
//! `verify SOURCE` checks the mounted secret; `stage SOURCE DESTINATION` copies it to a new file
//! owned by the panel user. Every check works on file descriptors so a path swapped in between
//! cannot be followed. Failures print `stage-secret: <message>` on stderr and exit 64.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

pub const SOURCE_UID: u32 = 0;
pub const SOURCE_GID: u32 = 10005;
pub const SOURCE_MODE: u32 = 0o440;
pub const TARGET_UID: u32 = 10001;
/// The image's `panel` system group.
pub const TARGET_GID: u32 = 101;
pub const TARGET_MODE: u32 = 0o400;
pub const MIN_BYTES: u64 = 32;
pub const MAX_BYTES: u64 = 513;
/// The exit status of every failure.
pub const EXIT_FAILURE: i32 = 64;

/// Why staging failed.
#[derive(Debug)]
pub enum StageError {
    /// A refused source or destination (`StageError` in Python).
    Refused(String),
    /// The operating system refused a call; rendered like Python's `OSError`
    /// (`[Errno 2] No such file or directory: '/path'`).
    Os { error: io::Error, path: Option<PathBuf> },
}

impl StageError {
    pub const NOT_REGULAR: &'static str = "Mieru token source must be a regular non-symlink file";
    pub const LINKS: &'static str = "Mieru token source must have exactly one link";
    pub const OWNER_MODE: &'static str = "Mieru token source must have owner 0:10005 and mode 0440";
    pub const SIZE: &'static str = "Mieru token source must be 32..513 bytes";
    pub const CHANGED: &'static str = "Mieru token source changed during staging";
    pub const FINAL_CHECK: &'static str = "staged Mieru token failed final identity or metadata check";

    fn refused(message: &str) -> Self {
        StageError::Refused(message.to_string())
    }

    fn os(path: Option<&Path>) -> impl FnOnce(io::Error) -> Self + '_ {
        move |error| StageError::Os { error, path: path.map(Path::to_path_buf) }
    }
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageError::Refused(message) => f.write_str(message),
            StageError::Os { error, path } => {
                let Some(errno) = error.raw_os_error() else {
                    return write!(f, "{error}");
                };
                // io::Error renders strerror(errno) followed by " (os error N)".
                let text = error.to_string();
                let strerror = text.strip_suffix(&format!(" (os error {errno})")).unwrap_or(&text);
                write!(f, "[Errno {errno}] {strerror}")?;
                if let Some(path) = path {
                    write!(f, ": {}", panel_core::pytext::repr(&path.to_string_lossy()))?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for StageError {}

/// `validate_source(info)`.
pub fn validate_source(info: &Metadata) -> Result<(), StageError> {
    if !info.file_type().is_file() {
        return Err(StageError::refused(StageError::NOT_REGULAR));
    }
    if info.nlink() != 1 {
        return Err(StageError::refused(StageError::LINKS));
    }
    if (info.uid(), info.gid(), info.mode() & 0o7777) != (SOURCE_UID, SOURCE_GID, SOURCE_MODE) {
        return Err(StageError::refused(StageError::OWNER_MODE));
    }
    if !(MIN_BYTES..=MAX_BYTES).contains(&info.size()) {
        return Err(StageError::refused(StageError::SIZE));
    }
    Ok(())
}

/// `open_source(path)`: opened `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`, then validated through the
/// descriptor.
pub fn open_source(path: &Path) -> Result<File, StageError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(StageError::os(Some(path)))?;
    validate_source(&file.metadata().map_err(StageError::os(None))?)?;
    Ok(file)
}

/// `verify(path)`.
pub fn verify(path: &Path) -> Result<(), StageError> {
    open_source(path).map(drop)
}

/// `stage(source, destination)`: copy the validated source into a newly created destination
/// (`O_EXCL|O_NOFOLLOW`, mode 0400), give it to 10001:101 with mode 0400, fsync it, and re-check
/// both ends; on any failure the destination is removed if it is still the file created here.
pub fn stage(source: &Path, destination: &Path) -> Result<(), StageError> {
    let mut source_file = open_source(source)?;
    let mut created: Option<(u64, u64)> = None;
    let result = stage_into(&mut source_file, destination, &mut created);
    if result.is_err() {
        if let Some(identity) = created {
            if let Ok(current) = fs::symlink_metadata(destination) {
                if (current.dev(), current.ino()) == identity {
                    let _ = fs::remove_file(destination);
                }
            }
        }
    }
    result
}

fn stage_into(source: &mut File, destination: &Path, created: &mut Option<(u64, u64)>) -> Result<(), StageError> {
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(TARGET_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
        .map_err(StageError::os(Some(destination)))?;
    let info = target.metadata().map_err(StageError::os(None))?;
    *created = Some((info.dev(), info.ino()));
    let mut total: u64 = 0;
    let mut buffer = [0u8; 65536];
    loop {
        let want = (MAX_BYTES + 1 - total).min(buffer.len() as u64) as usize;
        let read = loop {
            match source.read(&mut buffer[..want]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                other => break other.map_err(StageError::os(None))?,
            }
        };
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_BYTES {
            return Err(StageError::refused(StageError::CHANGED));
        }
        target.write_all(&buffer[..read]).map_err(StageError::os(None))?;
    }
    let source_final = source.metadata().map_err(StageError::os(None))?;
    validate_source(&source_final)?;
    if total != source_final.size() {
        return Err(StageError::refused(StageError::CHANGED));
    }
    std::os::unix::fs::fchown(&target, Some(TARGET_UID), Some(TARGET_GID)).map_err(StageError::os(None))?;
    target.set_permissions(fs::Permissions::from_mode(TARGET_MODE)).map_err(StageError::os(None))?;
    target.sync_all().map_err(StageError::os(None))?;
    let last = target.metadata().map_err(StageError::os(None))?;
    let at_path = fs::symlink_metadata(destination).map_err(StageError::os(Some(destination)))?;
    let good = last.file_type().is_file()
        && last.nlink() == 1
        && (last.uid(), last.gid(), last.mode() & 0o7777, last.size()) == (TARGET_UID, TARGET_GID, TARGET_MODE, total)
        && (at_path.dev(), at_path.ino()) == (last.dev(), last.ino())
        && at_path.file_type().is_file()
        && at_path.nlink() == 1;
    if !good {
        return Err(StageError::refused(StageError::FINAL_CHECK));
    }
    Ok(())
}

/// The command: `<program> verify SOURCE` or `<program> stage SOURCE DESTINATION` (`args` without
/// the program name). Prints failures as `stage-secret: <message>` on stderr; the exit status
/// (0 or [`EXIT_FAILURE`]).
pub fn main(program: &str, args: &[OsString]) -> i32 {
    let result = match args {
        [command, source] if command == "verify" => verify(Path::new(source)),
        [command, source, destination] if command == "stage" => stage(Path::new(source), Path::new(destination)),
        _ => Err(StageError::Refused(format!("usage: {program} verify SOURCE | stage SOURCE DESTINATION"))),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(io::stderr(), "stage-secret: {error}");
            EXIT_FAILURE
        }
    }
}
