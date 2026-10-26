//! `*at(2)` system calls on directory descriptors: every extraction step names its target
//! relative to a descriptor that was validated once, so a swapped path component cannot
//! redirect a write.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

fn cstr(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// `O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`.
pub const DIRECTORY_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;

/// Opens an absolute directory path (the anchor's `/`).
pub fn open_path(path: &[u8]) -> io::Result<OwnedFd> {
    let path = cstr(path)?;
    // SAFETY: valid C string; the returned descriptor is owned below.
    let fd = check(unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) })?;
    // SAFETY: `fd` was just returned by open and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens directory `name` below `parent`, refusing a symlink.
pub fn open_dir_at(parent: RawFd, name: &[u8]) -> io::Result<OwnedFd> {
    let name = cstr(name)?;
    // SAFETY: valid descriptor and C string.
    let fd = check(unsafe { libc::openat(parent, name.as_ptr(), DIRECTORY_FLAGS) })?;
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `lstat` relative to `parent`.
pub fn stat_at(parent: RawFd, name: &[u8]) -> io::Result<libc::stat> {
    let name = cstr(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor, C string and output buffer.
    check(unsafe { libc::fstatat(parent, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    // SAFETY: fstatat filled the buffer.
    Ok(unsafe { stat.assume_init() })
}

pub fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptor and output buffer.
    check(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })?;
    // SAFETY: fstat filled the buffer.
    Ok(unsafe { stat.assume_init() })
}

pub fn mkdir_at(parent: RawFd, name: &[u8], mode: u32) -> io::Result<()> {
    let name = cstr(name)?;
    // SAFETY: valid descriptor and C string.
    check(unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) }).map(|_| ())
}

pub fn rename_at(parent: RawFd, from: &[u8], to: &[u8]) -> io::Result<()> {
    let (from, to) = (cstr(from)?, cstr(to)?);
    // SAFETY: valid descriptor and C strings.
    check(unsafe { libc::renameat(parent, from.as_ptr(), parent, to.as_ptr()) }).map(|_| ())
}

/// `unlinkat`, with `AT_REMOVEDIR` for a directory.
pub fn unlink_at(parent: RawFd, name: &[u8], directory: bool) -> io::Result<()> {
    let name = cstr(name)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: valid descriptor and C string.
    check(unsafe { libc::unlinkat(parent, name.as_ptr(), flags) }).map(|_| ())
}

pub fn symlink_at(target: &[u8], parent: RawFd, name: &[u8]) -> io::Result<()> {
    let (target, name) = (cstr(target)?, cstr(name)?);
    // SAFETY: valid descriptor and C strings.
    check(unsafe { libc::symlinkat(target.as_ptr(), parent, name.as_ptr()) }).map(|_| ())
}

/// A new regular file below `parent`: `O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW`, `mode`.
pub fn create_file_at(parent: RawFd, name: &[u8], mode: u32) -> io::Result<File> {
    let name = cstr(name)?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: valid descriptor and C string.
    let fd = check(unsafe { libc::openat(parent, name.as_ptr(), flags, mode as libc::c_uint) })?;
    // SAFETY: fresh descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn fchmod(fd: RawFd, mode: u32) -> io::Result<()> {
    // SAFETY: plain syscall on a valid descriptor.
    check(unsafe { libc::fchmod(fd, mode as libc::mode_t) }).map(|_| ())
}

pub fn fsync(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain syscall on a valid descriptor.
    check(unsafe { libc::fsync(fd) }).map(|_| ())
}

pub fn dup(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the result is owned below.
    let copy = check(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// The names in the directory open at `fd` (without `.` and `..`).
pub fn list(fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let copy = dup(fd)?;
    // SAFETY: `fdopendir` takes ownership of the duplicate on success.
    let dir = unsafe { libc::fdopendir(copy.as_raw_fd()) };
    if dir.is_null() {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(copy);
    // SAFETY: `dir` is a valid DIR*; rewind in case the descriptor's offset moved.
    unsafe { libc::rewinddir(dir) };
    let mut names = Vec::new();
    loop {
        // SAFETY: reading a valid DIR*; errno distinguishes the end from an error.
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: closing the DIR* we opened.
            unsafe { libc::closedir(dir) };
            if err.raw_os_error().unwrap_or(0) != 0 {
                return Err(err);
            }
            return Ok(names);
        }
        // SAFETY: `d_name` is a NUL-terminated array inside the entry.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(name);
        }
    }
}

/// `(st_dev, st_ino)`.
pub fn identity(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev, stat.st_ino)
}

pub fn is_dir(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub fn is_symlink(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

pub fn is_regular(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}
