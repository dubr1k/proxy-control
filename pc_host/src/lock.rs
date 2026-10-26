//! The host operation lock (`installer/transaction.py:187-219`).
//!
//! One BSD `flock(2)` on `<root>/run/lock/proxy-control.lock` serialises every host mutation:
//! installer apply/resume/repair/uninstall, `reconcile-panel-update` and the version-agent's
//! panel update. It is `flock`, not `fcntl` record locking, so the Python installer, a Python
//! agent and the Rust binaries exclude each other during the 3.x → 4.0 transition.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::TxError;
use crate::fs::{ensure_parent, root_path};

/// Host path of the lock file.
pub const LOCK_PATH: &str = "/run/lock/proxy-control.lock";
/// The message every busy caller sees (Python's `TransactionBusyError`; the agent re-raises it
/// as its own `UpdateError` with the same text).
pub const BUSY_MESSAGE: &str = "another proxyctl operation is in progress";
/// The lock file is a symlink, a hard link or not a regular file.
pub const UNSAFE_LOCK_MESSAGE: &str = "operation lock must be a contained regular file";

/// The held lock; dropping it unlocks (`LOCK_UN`) and closes the descriptor. The file itself is
/// never removed (it lives on tmpfs).
#[derive(Debug)]
pub struct OperationLock {
    file: File,
    path: PathBuf,
}

impl OperationLock {
    /// Where the lock file is.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by `self.file` and still open.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// `operation_lock(root)`: take the lock without waiting.
///
/// 1. Missing parents of `<root>/run/lock/proxy-control.lock` are created; a symlink at the lock
///    path is `OwnershipError(UNSAFE_LOCK_MESSAGE)`.
/// 2. `open(O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC, 0600)`; children never inherit it.
/// 3. Not a regular file, or `st_nlink != 1` (a hard link to something else) → the same error.
/// 4. `fchmod(0600)` on every acquisition, then `flock(LOCK_EX|LOCK_NB)`; held elsewhere →
///    `TransactionBusyError(BUSY_MESSAGE)`. No timeout, no retry.
pub fn operation_lock(root: &Path) -> Result<OperationLock, TxError> {
    let path = root_path(root, LOCK_PATH)?;
    ensure_parent(&path)?;
    let symlink = |p: &Path| fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false);
    if symlink(&path) {
        return Err(TxError::Ownership(UNSAFE_LOCK_MESSAGE.into()));
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(err) => {
            if symlink(&path) {
                return Err(TxError::Ownership(UNSAFE_LOCK_MESSAGE.into()));
            }
            return Err(TxError::Io(err));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(TxError::Ownership(UNSAFE_LOCK_MESSAGE.into()));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    // SAFETY: the descriptor is owned by `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(TxError::Busy(BUSY_MESSAGE.into()));
        }
        return Err(TxError::Io(err));
    }
    Ok(OperationLock { file, path })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn excludes_a_second_holder_and_releases_on_drop() {
        let dir = TempDir::new("lock");
        let held = operation_lock(dir.path()).unwrap();
        let path = dir.path().join("run/lock/proxy-control.lock");
        assert_eq!(held.path(), path);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        // flock locks belong to the open file description: a second open in the same process
        // is excluded, exactly as a second process is.
        let err = operation_lock(dir.path()).unwrap_err();
        assert!(err.is_busy());
        assert_eq!(err.to_string(), BUSY_MESSAGE);
        assert_eq!(err.python_class_name(), "TransactionBusyError");
        drop(held);
        let again = operation_lock(dir.path()).unwrap();
        drop(again);
        assert!(path.exists(), "the lock file is never removed");
    }

    #[test]
    fn mode_is_restored_on_every_acquisition() {
        let dir = TempDir::new("lock-mode");
        drop(operation_lock(dir.path()).unwrap());
        let path = dir.path().join("run/lock/proxy-control.lock");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        drop(operation_lock(dir.path()).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
    }

    #[test]
    fn refuses_symlinks_hard_links_and_directories() {
        let dir = TempDir::new("lock-unsafe");
        let lock_dir = dir.path().join("run/lock");
        fs::create_dir_all(&lock_dir).unwrap();
        let target = dir.path().join("outside.lock");
        fs::write(&target, b"outside").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let path = lock_dir.join("proxy-control.lock");
        let untouched = || {
            assert_eq!(fs::read(&target).unwrap(), b"outside");
            assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o7777, 0o644);
        };

        // operation_lock_rejects_final_symlink_without_chmod_or_flock
        symlink(&target, &path).unwrap();
        let err = operation_lock(dir.path()).unwrap_err();
        assert_eq!(err.to_string(), UNSAFE_LOCK_MESSAGE);
        assert_eq!(err.python_class_name(), "OwnershipError");
        untouched();
        fs::remove_file(&path).unwrap();

        // operation_lock_rejects_hard_link_before_chmod_or_flock
        fs::hard_link(&target, &path).unwrap();
        assert_eq!(operation_lock(dir.path()).unwrap_err().to_string(), UNSAFE_LOCK_MESSAGE);
        untouched();
        fs::remove_file(&path).unwrap();

        fs::create_dir(&path).unwrap();
        assert!(operation_lock(dir.path()).is_err());
    }

    #[test]
    fn the_lock_is_not_inherited_by_children() {
        let dir = TempDir::new("lock-cloexec");
        let held = operation_lock(dir.path()).unwrap();
        let fd = held.file.as_raw_fd();
        // SAFETY: plain fcntl on an owned descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
