use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
struct Trusted(PathBuf);
impl Trusted {
    fn new() -> Self {
        assert_eq!(unsafe { libc::geteuid() }, 0, "helper ownership tests require the isolated root lab");
        let path = PathBuf::from("/root").join(format!("proxy-helper-test-{}", pc_host::fs::token_hex::<8>()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, size: usize) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, vec![b'x'; size]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}
impl Drop for Trusted {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn chown(path: &Path, uid: u32, gid: u32) {
    let value = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(value.as_ptr(), uid, gid) }, 0);
}
#[test]
fn state_preparer_refuses_unnormalized_and_relative_paths() {
    for value in
        ["relative/path", "/", "/var/lib/../etc", "/var/lib/naive/", "//etc/state", "/etc//state", "/etc/./state"]
    {
        assert!(normalized(value, "state directory").is_err(), "{value}");
    }
    normalized("/var/lib/naive-manager", "state directory").unwrap();
}
#[test]
fn prepare_token_changes_only_metadata_and_verify_is_nonmutating() {
    let dir = Trusted::new();
    let path = dir.file("token", 65);
    let before = fs::read(&path).unwrap();
    prepare_mieru_token(true, text(&path)).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!((metadata.uid(), metadata.gid(), mode(&metadata)), (0, 10005, 0o440));
    assert_eq!(fs::read(&path).unwrap(), before);
    prepare_mieru_token(false, text(&path)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(prepare_mieru_token(false, text(&path)).is_err());
    assert_eq!(mode(&fs::metadata(path).unwrap()), 0o400);
}
#[test]
fn token_preparer_refuses_unsafe_paths_without_creating_them() {
    for path in ["relative-token", "/tmp/../tmp/token", "/", "//etc/token", "/etc/token/"] {
        assert!(prepare_mieru_token(true, path).is_err());
    }
}
#[test]
fn token_preparer_refuses_symlink_and_wrong_size() {
    let dir = Trusted::new();
    let target = dir.file("target", 32);
    let link = dir.0.join("link");
    symlink(&target, &link).unwrap();
    assert!(prepare_mieru_token(true, text(&link)).is_err());
    assert_eq!(fs::metadata(&target).unwrap().gid(), 0);
    for size in [0, 31, 514, 4096] {
        let file = dir.file(&format!("size-{size}"), size);
        assert!(prepare_mieru_token(true, text(&file)).is_err());
    }
    for size in [32, 513] {
        let file = dir.file(&format!("size-{size}"), size);
        prepare_mieru_token(true, text(&file)).unwrap();
    }
}
#[test]
fn token_preparer_refuses_non_root_owner_without_mutation() {
    let dir = Trusted::new();
    let file = dir.file("token", 32);
    chown(&file, 10003, 10003);
    assert!(prepare_mieru_token(true, text(&file)).is_err());
    let info = fs::metadata(file).unwrap();
    assert_eq!((info.uid(), info.gid(), mode(&info)), (10003, 10003, 0o600));
}
#[test]
fn token_preparer_rejects_hardlink_without_mutating_alias() {
    let dir = Trusted::new();
    let file = dir.file("token", 32);
    let alias = dir.0.join("alias");
    fs::hard_link(&file, &alias).unwrap();
    assert!(prepare_mieru_token(true, text(&file)).unwrap_err().0.contains("hardlink"));
    let info = fs::metadata(alias).unwrap();
    assert_eq!((info.gid(), mode(&info), info.nlink()), (0, 0o600, 2));
}
#[test]
fn token_preparer_rejects_writable_or_symlinked_parent() {
    let dir = Trusted::new();
    let file = dir.file("token", 32);
    for permissions in [0o720, 0o702, 0o777] {
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(permissions)).unwrap();
        assert!(prepare_mieru_token(true, text(&file)).is_err());
    }
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.0.join("link");
    symlink(&dir.0, &link).unwrap();
    assert!(prepare_mieru_token(true, text(&link.join("token"))).is_err());
    assert_eq!(fs::metadata(&file).unwrap().gid(), 0);
}
#[test]
fn token_preparer_detects_path_swap_and_never_mutates_victim() {
    let dir = Trusted::new();
    let token = dir.file("token", 32);
    let victim = dir.file("victim", 32);
    let entry = Entry::open(text(&token), "token file", 0o022).unwrap();
    let fd = entry.fd(false).unwrap();
    token_source(&stat_fd(&fd).unwrap()).unwrap();
    mutate(&fd, 0, 10005, 0o440).unwrap();
    fs::rename(&token, dir.0.join("moved-token")).unwrap();
    symlink(&victim, &token).unwrap();
    assert!(entry.unchanged(&fd).unwrap_err().0.contains("identity changed"));
    let info = fs::metadata(victim).unwrap();
    assert_eq!((info.uid(), info.gid(), mode(&info)), (0, 0, 0o600));
}
#[test]
fn naive_state_preparer_creates_exact_boundaries_and_preserves_restore() {
    let dir = Trusted::new();
    let state = dir.0.join("state");
    let logs = dir.0.join("logs");
    assert_eq!(prepare_naive_state(true, text(&state), text(&logs)).unwrap(), (true, true));
    assert_eq!(prepare_naive_state(true, text(&state), text(&logs)).unwrap(), (false, false));
    for (path, uid, gid, permissions) in [(&state, 10002, 101, 0o700), (&logs, 10003, 10004, 0o750)] {
        let info = fs::metadata(path).unwrap();
        assert_eq!((info.uid(), info.gid(), mode(&info)), (uid, gid, permissions));
    }
    for (name, permissions) in [
        ("Caddyfile", 0o640),
        ("manager-token", 0o400),
        ("xray-router-ingress", 0o400),
        ("users.json", 0o600),
        ("transaction.json", 0o600),
        ("traffic.sqlite3", 0o600),
        ("traffic.sqlite3-wal", 0o600),
        ("traffic.sqlite3-shm", 0o600),
    ] {
        let file = state.join(name);
        fs::write(&file, b"opaque restore").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(permissions)).unwrap();
        chown(&file, 10002, 101);
    }
    let backups = state.join("backups");
    fs::create_dir(&backups).unwrap();
    fs::set_permissions(&backups, fs::Permissions::from_mode(0o700)).unwrap();
    chown(&backups, 10002, 101);
    let backup = backups.join("paired.json");
    fs::write(&backup, b"opaque backup").unwrap();
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
    chown(&backup, 10002, 101);
    let log = logs.join("access.json");
    fs::write(&log, b"opaque log").unwrap();
    chown(&log, 10003, 10004);
    fs::set_permissions(&log, fs::Permissions::from_mode(0o640)).unwrap();
    prepare_naive_state(false, text(&state), text(&logs)).unwrap();
    assert_eq!(fs::read(backup).unwrap(), b"opaque backup");
}
#[test]
fn naive_state_preparer_refuses_symlinks_foreign_files_hardlinks_and_wrong_mode() {
    for variant in ["foreign", "symlink", "hardlink", "mode", "owner", "transaction"] {
        let dir = Trusted::new();
        let state = dir.0.join("state");
        let logs = dir.0.join("logs");
        prepare_naive_state(true, text(&state), text(&logs)).unwrap();
        let file = state.join(if variant == "foreign" {
            "foreign"
        } else if variant == "transaction" {
            "transaction.json"
        } else {
            "users.json"
        });
        fs::write(&file, b"preserve").unwrap();
        chown(&file, 10002, 101);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        match variant {
            "symlink" => {
                fs::remove_file(&file).unwrap();
                symlink(dir.file("victim", 32), &file).unwrap();
            }
            "hardlink" => fs::hard_link(&file, state.join("traffic.sqlite3")).unwrap(),
            "mode" => fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(),
            "owner" => chown(&file, 0, 0),
            _ => (),
        };
        assert!(prepare_naive_state(false, text(&state), text(&logs)).is_err(), "{variant}");
    }
}
#[test]
fn naive_state_preparer_refuses_unreadable_writable_or_foreign_logs() {
    for permissions in [0o600, 0o660, 0o644, 0o777] {
        let dir = Trusted::new();
        let state = dir.0.join("state");
        let logs = dir.0.join("logs");
        prepare_naive_state(true, text(&state), text(&logs)).unwrap();
        let log = logs.join("access.json");
        fs::write(&log, b"preserve").unwrap();
        chown(&log, 10003, 10004);
        fs::set_permissions(&log, fs::Permissions::from_mode(permissions)).unwrap();
        assert!(prepare_naive_state(false, text(&state), text(&logs)).is_err());
        assert_eq!(mode(&fs::metadata(&log).unwrap()), permissions);
    }
}
#[test]
fn naive_state_preparer_refuses_missing_verification_and_equal_paths() {
    let dir = Trusted::new();
    assert!(prepare_naive_state(false, text(&dir.0.join("state")), text(&dir.0.join("logs"))).is_err());
    assert!(prepare_naive_state(true, text(&dir.0.join("state")), text(&dir.0.join("state"))).is_err());
}
#[test]
fn helper_cli_preserves_error_status_and_secret_free_messages() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(cli(&["prepare-mieru-token".into(), "verify".into(), "relative".into()], &mut out, &mut err), Some(1));
    assert!(out.is_empty());
    assert!(String::from_utf8(err).unwrap().starts_with("prepare-mieru-token:"));
}
