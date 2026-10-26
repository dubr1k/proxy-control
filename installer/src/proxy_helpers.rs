//! FD-bound host preparers replacing prepare-naive-state.py and prepare_mieru_token.py.
//! Parent and leaf identities stay anchored throughout validation and mutation; no recursive chown.
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct BoundaryError(pub String);
impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for BoundaryError {}
impl From<io::Error> for BoundaryError {
    fn from(error: io::Error) -> Self { Self(error.to_string()) }
}
type Result<T> = std::result::Result<T, BoundaryError>;
fn fail<T>(message: impl Into<String>) -> Result<T> { Err(BoundaryError(message.into())) }
fn cstring(value: &str) -> Result<CString> { CString::new(value).map_err(|_| BoundaryError("path contains NUL".into())) }
fn checked_fd(fd: RawFd) -> Result<OwnedFd> {
    if fd < 0 { return Err(io::Error::last_os_error().into()); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
fn stat_fd(fd: &OwnedFd) -> Result<fs::Metadata> { Ok(File::from(fd.try_clone()?).metadata()?) }
fn mode(metadata: &fs::Metadata) -> u32 { metadata.mode() & 0o7777 }
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool { a.dev() == b.dev() && a.ino() == b.ino() }
fn normalized(value: &str, label: &str) -> Result<()> {
    if !value.starts_with('/') { return fail(format!("{label} must be an absolute path")); }
    if value == "/" { return fail(format!("{label} must not be the filesystem root")); }
    if value.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..") {
        return fail(format!("{label} must be a normalized absolute path without traversal"));
    }
    Ok(())
}
struct Entry { parent: OwnedFd, name: CString, path: PathBuf }
impl Entry {
    fn open(path: &str, label: &str, forbidden: u32) -> Result<Self> {
        normalized(path, label)?;
        let parts: Vec<_> = path.split('/').skip(1).collect();
        let root = cstring("/")?;
        let mut parent = checked_fd(unsafe { libc::open(root.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) })?;
        let mut cursor = PathBuf::from("/");
        for component in std::iter::once("").chain(parts[..parts.len()-1].iter().copied()) {
            if !component.is_empty() {
                cursor.push(component);
                let component = cstring(component)?;
                parent = checked_fd(unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) })
                    .map_err(|_| BoundaryError(format!("{label} parent is missing, symlinked or not a directory: {}", cursor.display())))?;
            }
            let info = stat_fd(&parent)?;
            if info.uid() != 0 { return fail(format!("{label} parent must be root-owned: {}", cursor.display())); }
            if mode(&info) & forbidden != 0 { return fail(format!("{label} parent must not be writable by untrusted identities: {}", cursor.display())); }
        }
        Ok(Self { parent, name: cstring(parts[parts.len()-1])?, path: PathBuf::from(path) })
    }
    fn fd(&self, directory: bool) -> Result<OwnedFd> {
        checked_fd(unsafe { libc::openat(self.parent.as_raw_fd(), self.name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | if directory { libc::O_DIRECTORY } else { 0 }) })
    }
    fn exists(&self) -> Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstatat(self.parent.as_raw_fd(), self.name.as_ptr(), info.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
        if result == 0 { return Ok(true); }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound { Ok(false) } else { Err(error.into()) }
    }
    fn unchanged(&self, fd: &OwnedFd) -> Result<()> {
        let info = stat_fd(fd)?;
        let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstatat(self.parent.as_raw_fd(), self.name.as_ptr(), current.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return fail("path identity changed during operation");
        }
        let current = unsafe { current.assume_init() };
        if current.st_dev as u64 != info.dev() || current.st_ino as u64 != info.ino() || current.st_mode & libc::S_IFMT != info.mode() & libc::S_IFMT {
            return fail("path identity changed during operation");
        }
        Ok(())
    }
}
fn mutate(fd: &OwnedFd, uid: u32, gid: u32, permissions: u32) -> Result<()> {
    if unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) } != 0 || unsafe { libc::fchmod(fd.as_raw_fd(), permissions) } != 0 || unsafe { libc::fsync(fd.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
fn token_source(info: &fs::Metadata) -> Result<()> {
    if !info.is_file() { return fail("token path must be an existing regular non-symlink file"); }
    if info.uid() != 0 { return fail("token file must be owned by root"); }
    if info.nlink() != 1 { return fail("token file must have exactly one link (hardlinks are forbidden)"); }
    if !(32..=513).contains(&info.len()) { return fail("token file must be 32..513 bytes"); }
    Ok(())
}
pub fn prepare_mieru_token(prepare: bool, path: &str) -> Result<()> {
    let entry = Entry::open(path, "token file", 0o022)?;
    let fd = entry.fd(false)?;
    token_source(&stat_fd(&fd)?)?;
    if prepare { mutate(&fd, 0, 10005, 0o440)?; }
    let final_info = stat_fd(&fd)?;
    token_source(&final_info)?;
    if (final_info.uid(), final_info.gid(), mode(&final_info)) != (0, 10005, 0o440) { return fail("token file must have owner 0:10005 and mode 0440"); }
    entry.unchanged(&fd).map_err(|_| BoundaryError("token path identity changed during operation".into()))
}
fn identity(kind: &str, id: u32, expected: &str) -> Result<()> {
    // getpwuid_r/getgrgid_r avoid global libc storage and expose only the subject name.
    let mut storage = vec![0u8; 65536];
    let name = if kind == "UID" {
        let mut value = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let code = unsafe { libc::getpwuid_r(id, value.as_mut_ptr(), storage.as_mut_ptr().cast(), storage.len(), &mut result) };
        if code != 0 { return Err(io::Error::from_raw_os_error(code).into()); }
        if result.is_null() { return Ok(()); }
        unsafe { CStr::from_ptr((*result).pw_name) }.to_string_lossy().into_owned()
    } else {
        let mut value = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut result = std::ptr::null_mut();
        let code = unsafe { libc::getgrgid_r(id, value.as_mut_ptr(), storage.as_mut_ptr().cast(), storage.len(), &mut result) };
        if code != 0 { return Err(io::Error::from_raw_os_error(code).into()); }
        if result.is_null() { return Ok(()); }
        unsafe { CStr::from_ptr((*result).gr_name) }.to_string_lossy().into_owned()
    };
    if name != expected { return fail(format!("{kind} {id} collision: {name}")); }
    Ok(())
}
fn directory(entry: &Entry, prepare: bool, uid: u32, gid: u32, permissions: u32, label: &str) -> Result<(OwnedFd, bool)> {
    let created = !entry.exists()?;
    if created {
        if !prepare { return fail(format!("verify requires an existing {label}; run prepare first")); }
        if unsafe { libc::mkdirat(entry.parent.as_raw_fd(), entry.name.as_ptr(), permissions) } != 0 { return Err(io::Error::last_os_error().into()); }
    }
    let fd = entry.fd(true).map_err(|_| BoundaryError(format!("{label} must be a real directory, not a symlink: {}", entry.path.display())))?;
    if created { mutate(&fd, uid, gid, permissions)?; }
    let info = stat_fd(&fd)?;
    if (info.uid(), info.gid()) != (uid, gid) { return fail(format!("{label} must have owner {uid}:{gid}: {}", entry.path.display())); }
    if mode(&info) != permissions { return fail(format!("{label} must have mode {permissions:04o}: {}", entry.path.display())); }
    entry.unchanged(&fd)?;
    Ok((fd, created))
}
fn children(fd: &OwnedFd) -> Result<Vec<String>> {
    let mut values = Vec::new();
    // Linux /proc is only used to enumerate an already opened directory; children open via openat.
    for child in fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))? {
        values.push(child?.file_name().into_string().map_err(|_| BoundaryError("foreign non-UTF-8 state entry".into()))?);
    }
    values.sort();
    Ok(values)
}
fn child(parent: &OwnedFd, name: &str, path: PathBuf) -> Result<Entry> { Ok(Entry { parent: parent.try_clone()?, name: cstring(name)?, path }) }
fn state_file(entry: &Entry, permissions: u32, label: &str) -> Result<()> {
    let fd = entry.fd(false).map_err(|_| BoundaryError(format!("{label} must be a regular file, not a symlink: {}", entry.path.display())))?;
    let info = stat_fd(&fd)?;
    if !info.is_file() { return fail(format!("{label} must be a regular file, not a symlink: {}", entry.path.display())); }
    if info.nlink() != 1 { return fail(format!("{label} must not be hardlinked: {}", entry.path.display())); }
    if (info.uid(), info.gid()) != (10002, 101) { return fail(format!("{label} must have owner 10002:101: {}", entry.path.display())); }
    if mode(&info) != permissions { return fail(format!("{label} must have mode {permissions:04o}: {}", entry.path.display())); }
    entry.unchanged(&fd)
}
fn owned_state(fd: &OwnedFd, path: &Path) -> Result<()> {
    let names = children(fd)?;
    for name in &names {
        let entry = child(fd, name, path.join(name))?;
        if name == "backups" {
            let (backups, _) = directory(&entry, false, 10002, 101, 0o700, "backups directory")?;
            for name in children(&backups)? { state_file(&child(&backups, &name, entry.path.join(&name))?, 0o600, "recovery backup")?; }
            entry.unchanged(&backups)?;
        } else {
            let permissions = match name.as_str() {
                "Caddyfile" => 0o640,
                "manager-token" | "xray-router-ingress" => 0o400,
                "users.json" | "transaction.json" | "traffic.sqlite3" | "traffic.sqlite3-wal" | "traffic.sqlite3-shm" => 0o600,
                _ => return fail(format!("foreign entry in manager state: {}", entry.path.display())),
            };
            state_file(&entry, permissions, name)?;
        }
    }
    if names.iter().any(|v| v == "transaction.json") && !names.iter().any(|v| v == "users.json") { return fail("an unfinished transaction requires the paired users.json state"); }
    Ok(())
}
pub fn prepare_naive_state(prepare: bool, state: &str, logs: &str) -> Result<(bool, bool)> {
    normalized(state, "state directory")?;
    normalized(logs, "log directory")?;
    if state == logs { return fail("state and log directories must be distinct"); }
    identity("UID", 10003, "naive-caddy")?;
    identity("GID", 10004, "naive-accounting")?;
    let state_entry = Entry::open(state, "state directory", 0o002)?;
    let (state_fd, created_state) = directory(&state_entry, prepare, 10002, 101, 0o700, "state directory")?;
    owned_state(&state_fd, Path::new(state))?;
    let log_entry = Entry::open(logs, "log directory", 0o002)?;
    let (log_fd, created_log) = directory(&log_entry, prepare, 10003, 10004, 0o750, "log directory")?;
    for name in children(&log_fd)? {
        let entry = child(&log_fd, &name, Path::new(logs).join(&name))?;
        let fd = entry.fd(false).map_err(|_| BoundaryError(format!("access log must be a regular file, not a symlink: {}", entry.path.display())))?;
        let info = stat_fd(&fd)?;
        if !info.is_file() { return fail(format!("access log must be a regular file, not a symlink: {}", entry.path.display())); }
        if (info.uid(), info.gid()) != (10003, 10004) { return fail(format!("access log must have owner 10003:10004: {}", entry.path.display())); }
        if mode(&info) & 0o027 != 0 { return fail(format!("access log must stay group read-only: {}", entry.path.display())); }
        if mode(&info) & 0o040 == 0 { return fail(format!("access log must stay group readable: {}", entry.path.display())); }
        entry.unchanged(&fd)?;
    }
    state_entry.unchanged(&state_fd)?;
    log_entry.unchanged(&log_fd)?;
    // Keep the opened identity check explicit: an attacker cannot swap the pathname into a new tree.
    if !same(&stat_fd(&state_fd)?, &fs::symlink_metadata(state)?) || !same(&stat_fd(&log_fd)?, &fs::symlink_metadata(logs)?) { return fail("path identity changed during operation"); }
    Ok((created_state, created_log))
}

/// Separate helper CLI: keep the production script's messages/status, without constructing an engine.
pub fn cli(arguments: &[String], stdout: &mut dyn io::Write, stderr: &mut dyn io::Write) -> Option<i32> {
    let command = arguments.first()?.as_str();
    if !matches!(command, "prepare-naive-state" | "prepare-mieru-token") { return None; }
    if command=="prepare-naive-state" {
        use installer_core::argparse::{Arg,Choices,Help,Parser};
        let mut parser=Parser::new("proxy-control-installer prepare-naive-state",Some("Prepare or verify the NaiveProxy state and log boundary"));
        parser.add_positional("mode",Help::None,false,Some(Choices::strings(&["prepare","verify"])));
        parser.add_option(&["--state-dir"],false,Help::None,true,Arg::Str("/var/lib/naive-manager".into()));
        parser.add_option(&["--log-dir"],false,Help::None,true,Arg::Str("/var/log/naive-proxy".into()));
        let values=match parser.parse_args(&arguments[1..],installer_core::argparse::terminal_width()){
            Ok(values)=>values,
            Err(exit)=>{let _=stdout.write_all(exit.stdout.as_bytes());let _=stderr.write_all(exit.stderr.as_bytes());return Some(exit.status);}
        };
        let value=|key:&str|match values.get(key){Some(Arg::Str(value))=>value.as_str(),_=>""};
        let result=if unsafe{libc::geteuid()}!=0{fail("must run as root")}else{prepare_naive_state(value("mode")=="prepare",value("state_dir"),value("log_dir"))};
        return Some(match result{
            Ok(_)=>{let verb=if value("mode")=="prepare"{"Prepared"}else{"Verified"};let _=writeln!(stdout,"{verb} Naive manager state directory: {}\n{verb} Naive accounting log directory: {}",value("state_dir"),value("log_dir"));0},
            Err(error)=>{let _=writeln!(stderr,"prepare-naive-state: {error}");1}
        });
    }
    let result = (|| -> Result<String> {
        if unsafe { libc::geteuid() } != 0 { return fail("must run as root"); }
        let prepare = match arguments.get(1).map(String::as_str) { Some("prepare") => true, Some("verify") => false, _ => return fail("usage: prepare|verify followed by helper path options") };
        let verb = if prepare { "Prepared" } else { "Verified" };
        if arguments.len()!=3{return fail("usage: prepare-mieru-token prepare|verify absolute-token-file");}
        prepare_mieru_token(prepare,&arguments[2])?;
        Ok(format!("{verb} Mieru manager token metadata: {}\n",arguments[2]))
    })();
    Some(match result { Ok(text) => { let _ = stdout.write_all(text.as_bytes()); 0 }, Err(error) => { let _ = writeln!(stderr, "{command}: {error}"); 1 } })
}

#[cfg(test)]
#[path = "proxy_helpers_tests.rs"]
mod tests;
