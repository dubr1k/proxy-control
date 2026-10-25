//! Durable file operations of the manager: refuse symlinked parents and foreign files, write
//! through a private sibling, fsync the file and its directory, create missing directories
//! one by one and fsync each parent.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{Map, Value};

use crate::error::{Error, Result};

pub type PathHook = Box<dyn Fn(&Path) -> Result<()> + Send + Sync>;
pub type TransactionHook = Box<dyn Fn(&Map<String, Value>) -> Result<()> + Send + Sync>;
pub type Observer = Box<dyn Fn(&Path) + Send + Sync>;

/// Seams the Python suite reached through `monkeypatch`: a failing `_atomic_write`, a crash
/// right after a journal write, and a record of directory fsyncs and replaces.
#[derive(Default)]
pub struct Faults {
    pub before_write: Option<PathHook>,
    pub after_transaction: Option<TransactionHook>,
    pub synced_directory: Option<Observer>,
    pub replaced: Option<Observer>,
}

/// The fault seams of one manager, consulted on every file operation.
#[derive(Default)]
pub struct Fs {
    pub faults: Mutex<Faults>,
}

fn temp_suffix() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the system random source is available");
    bytes.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char).collect()
}

/// `tempfile.mkstemp(prefix=…, dir=…)`: a new 0600 file with a random name.
pub fn mkstemp(dir: &Path, prefix: &str) -> std::io::Result<(File, PathBuf)> {
    loop {
        let path = dir.join(format!("{prefix}{}", temp_suffix()));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_CLOEXEC).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
}

/// `pathlib.Path.absolute()`: no symlink or `..` resolution.
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|dir| dir.join(path)).unwrap_or_else(|_| path.to_path_buf())
    }
}

fn parent_of(path: &Path) -> PathBuf {
    path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"))
}

/// Every directory from the root down to `path`'s parent, root excluded.
fn parent_chain(path: &Path) -> Vec<PathBuf> {
    let parent = parent_of(&absolute(path));
    let mut chain: Vec<PathBuf> = parent.ancestors().map(Path::to_path_buf).collect();
    chain.reverse();
    chain.into_iter().filter(|dir| dir.parent().is_some()).collect()
}

impl Fs {
    fn faults(&self) -> std::sync::MutexGuard<'_, Faults> {
        self.faults.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn fsync_directory(&self, path: &Path) -> Result<()> {
        let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
        if let Some(observe) = &self.faults().synced_directory {
            observe(path);
        }
        dir.sync_all()?;
        Ok(())
    }

    pub fn replace(&self, from: &Path, to: &Path) -> Result<()> {
        if let Some(observe) = &self.faults().replaced {
            observe(to);
        }
        fs::rename(from, to)?;
        Ok(())
    }

    /// `_durable_mkdir`: refuses a symlinked or non-directory ancestor, creates what is
    /// missing with `mode` and fsyncs each new directory's parent.
    pub fn durable_mkdir(&self, path: &Path, mode: u32) -> Result<()> {
        let mut missing = Vec::new();
        let mut current = path.to_path_buf();
        while !current.exists() {
            missing.push(current.clone());
            current = match current.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
                _ => PathBuf::from("."),
            };
        }
        if current.is_symlink() || !current.is_dir() {
            return Err(Error::conflict(format!("refusing unsafe directory: {}", current.display())));
        }
        for directory in missing.iter().rev() {
            fs::DirBuilder::new().mode(mode).create(directory)?;
            self.fsync_directory(&parent_of(directory))?;
        }
        Ok(())
    }

    /// `_atomic_write`: sibling temp file with exactly `mode`, fsync, replace, fsync the
    /// directory; the temp file is removed on any failure.
    pub fn atomic_write(&self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        if let Some(fault) = &self.faults().before_write {
            fault(path)?;
        }
        assert_safe_parent_chain(path)?;
        let parent = parent_of(path);
        self.durable_mkdir(&parent, 0o700)?;
        assert_safe_parent_chain(path)?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (mut file, temporary) = mkstemp(&parent, &format!(".{name}."))?;
        let written = (|| -> Result<()> {
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            self.replace(&temporary, path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            self.fsync_directory(&parent)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written
    }

    /// `_durable_unlink`.
    pub fn durable_unlink(&self, path: &Path) -> Result<()> {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        let parent = parent_of(path);
        self.durable_mkdir(&parent, 0o700)?;
        self.fsync_directory(&parent)
    }

    pub fn after_transaction(&self, transaction: &Map<String, Value>) -> Result<()> {
        match &self.faults().after_transaction {
            Some(fault) => fault(transaction),
            None => Ok(()),
        }
    }
}

/// `_assert_safe_parent_chain`: no symlink or non-directory among the existing ancestors.
pub fn assert_safe_parent_chain(path: &Path) -> Result<()> {
    for directory in parent_chain(path) {
        let info = match fs::symlink_metadata(&directory) {
            Ok(info) => info,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if info.file_type().is_symlink() || !info.is_dir() {
            return Err(Error::conflict(format!("refusing unsafe directory: {}", directory.display())));
        }
    }
    Ok(())
}

/// `_assert_regular`: a regular file, not a symlink, not group- or world-writable.
pub fn assert_regular(path: &Path) -> Result<()> {
    assert_safe_parent_chain(path)?;
    let info = fs::symlink_metadata(path)?;
    if !info.file_type().is_file() || info.file_type().is_symlink() {
        return Err(Error::conflict(format!("refusing unsafe file: {}", path.display())));
    }
    if info.permissions().mode() & 0o022 != 0 {
        return Err(Error::conflict(format!("refusing writable config: {}", path.display())));
    }
    Ok(())
}

/// `Path.read_text()`: an undecodable file is a `ValueError` (`UnicodeDecodeError`).
pub fn read_text(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    String::from_utf8(bytes).map_err(|_| Error::value("'utf-8' codec can't decode the file"))
}

/// `Path.exists()`: follows symlinks; any error is "absent".
pub fn exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_sets_the_exact_mode_and_leaves_no_temp_file() {
        let dir = crate::tests::tempdir("fsops-write");
        let fs_ops = Fs::default();
        let path = dir.join("nested/deeper/file");
        fs_ops.atomic_write(&path, b"one", 0o640).unwrap();
        fs_ops.atomic_write(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        assert_eq!(fs::metadata(dir.join("nested")).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn symlinked_parents_and_writable_files_are_refused() {
        let dir = crate::tests::tempdir("fsops-unsafe");
        fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let err = Fs::default().atomic_write(&dir.join("link/file"), b"x", 0o600).unwrap_err();
        assert!(err.message().contains("unsafe"), "{err}");
        fs::write(dir.join("real/file"), "x").unwrap();
        fs::set_permissions(dir.join("real/file"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(assert_regular(&dir.join("real/file")).unwrap_err().message().contains("writable"));
        assert!(assert_regular(&dir.join("link/file")).unwrap_err().message().contains("unsafe"));
    }
}
