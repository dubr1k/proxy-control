//! `stage-secret` (`panel/stage_secret.py`): the ported `test_stage_secret_*` cases of
//! `tests/test_panel_entrypoint.py`. Owner checks need root (the lab host runs tests as root);
//! without it those tests return early.

mod common;

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use common::{is_root, TempDir};
use panel_secrets::stage_secret::{self, StageError, EXIT_FAILURE, SOURCE_GID, SOURCE_MODE, SOURCE_UID};

fn write_source(path: &Path, content: &[u8], mode: u32, uid: u32, gid: u32) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).unwrap();
}

#[test]
fn stage_secret_stages_real_file_with_private_metadata() {
    if !is_root() {
        return;
    }
    let dir = TempDir::new("stage");
    let (source, destination) = (dir.join("source"), dir.join("destination"));
    write_source(&source, &[b'm'; 32], SOURCE_MODE, SOURCE_UID, SOURCE_GID);
    stage_secret::verify(&source).unwrap();
    stage_secret::stage(&source, &destination).unwrap();
    let info = std::fs::metadata(&destination).unwrap();
    assert_eq!(std::fs::read(&destination).unwrap(), [b'm'; 32]);
    assert_eq!((info.uid(), info.gid(), info.mode() & 0o777, info.nlink()), (10001, 101, 0o400, 1));
    // The destination is created, never overwritten.
    let again = stage_secret::stage(&source, &destination).unwrap_err();
    assert!(again.to_string().starts_with("[Errno 17] File exists: '"), "{again}");
}

#[test]
fn stage_secret_rejects_invalid_source_without_creating_destination() {
    if !is_root() {
        return;
    }
    for defect in ["owner", "group", "mode", "short", "large", "hardlink", "symlink"] {
        let dir = TempDir::new("defect");
        let mut source = dir.join("source");
        let size = match defect {
            "large" => 514,
            "short" => 31,
            _ => 32,
        };
        write_source(
            &source,
            &vec![b'm'; size],
            if defect == "mode" { 0o600 } else { 0o440 },
            if defect == "owner" { 10003 } else { 0 },
            if defect == "group" { 0 } else { 10005 },
        );
        if defect == "hardlink" {
            std::fs::hard_link(&source, dir.join("alias")).unwrap();
        } else if defect == "symlink" {
            let link = dir.join("source-link");
            std::os::unix::fs::symlink(&source, &link).unwrap();
            source = link;
        }
        let destination = dir.join("destination");
        let error = stage_secret::stage(&source, &destination).unwrap_err();
        assert!(!destination.exists(), "{defect}");
        let expected = match defect {
            "owner" | "group" | "mode" => StageError::OWNER_MODE.to_string(),
            "short" | "large" => StageError::SIZE.to_string(),
            "hardlink" => StageError::LINKS.to_string(),
            _ => format!("[Errno 40] Too many levels of symbolic links: '{}'", source.display()),
        };
        assert_eq!(error.to_string(), expected, "{defect}");
        assert!(stage_secret::verify(&source).is_err(), "{defect}");
    }
}

#[test]
fn the_command_prints_python_messages_and_exits_64() {
    let dir = TempDir::new("command");
    let missing = dir.join("missing");
    let args = |items: &[&str]| -> Vec<OsString> { items.iter().map(OsString::from).collect() };
    assert_eq!(stage_secret::main("stage_secret.py", &args(&[])), EXIT_FAILURE);
    assert_eq!(stage_secret::main("stage_secret.py", &args(&["verify"])), EXIT_FAILURE);
    assert_eq!(stage_secret::main("stage_secret.py", &args(&["copy", "a", "b"])), EXIT_FAILURE);
    let missing_text = missing.to_str().unwrap();
    assert_eq!(stage_secret::main("stage_secret.py", &args(&["verify", missing_text])), EXIT_FAILURE);
    let error = stage_secret::verify(&missing).unwrap_err();
    assert_eq!(error.to_string(), format!("[Errno 2] No such file or directory: '{missing_text}'"));
    let directory = stage_secret::verify(dir.path()).unwrap_err();
    assert_eq!(directory.to_string(), StageError::NOT_REGULAR);
    if is_root() {
        let source = dir.join("source");
        write_source(&source, &[b'm'; 40], SOURCE_MODE, SOURCE_UID, SOURCE_GID);
        assert_eq!(stage_secret::main("x", &args(&["verify", source.to_str().unwrap()])), 0);
        let destination = dir.join("destination");
        let staged = args(&["stage", source.to_str().unwrap(), destination.to_str().unwrap()]);
        assert_eq!(stage_secret::main("x", &staged), 0);
        assert_eq!(std::fs::read(&destination).unwrap(), [b'm'; 40]);
    }
}
