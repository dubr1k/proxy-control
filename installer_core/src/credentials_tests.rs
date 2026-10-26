//! Ported from `tests/test_installer_credentials.py`.

use std::os::unix::fs::PermissionsExt;

use super::*;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "installer-core-credentials-{}-{}",
            std::process::id(),
            pc_host::fs::uuid4_hex()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn owner(password: &str) -> OperatorCredentials {
    OperatorCredentials::new(Some("owner"), Some(password), None, None).unwrap()
}

#[test]
fn credentials_live_next_to_the_configuration_under_a_predictable_name() {
    assert_eq!(
        credentials_path(Path::new("/etc/pc/install.toml")).unwrap(),
        PathBuf::from("/etc/pc/install.credentials")
    );
}

#[test]
fn a_written_file_is_private_and_reads_back_unchanged() {
    let dir = TempDir::new();
    let target = dir.0.join("install.toml");
    let given = OperatorCredentials::new(
        Some("owner"),
        Some("a-long-enough-password"),
        Some("xui-owner"),
        Some("another-long-password"),
    )
    .unwrap();
    let path = write_credentials(&target, &given).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(read_credentials(&target).unwrap(), Some(given));
}

#[test]
fn absent_credentials_are_not_an_error() {
    let dir = TempDir::new();
    assert_eq!(read_credentials(&dir.0.join("install.toml")).unwrap(), None);
}

#[test]
fn a_group_or_world_readable_file_is_refused() {
    let dir = TempDir::new();
    let target = dir.0.join("install.toml");
    let path = write_credentials(&target, &owner("a-long-password")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(read_credentials(&target).unwrap_err().0.contains("readable"));
}

#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    let dir = TempDir::new();
    let target = dir.0.join("install.toml");
    let path = credentials_path(&target).unwrap();
    std::fs::write(&path, "panel_password = \"x\"\nsurprise = \"y\"\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_credentials(&target).unwrap_err().0, "unknown credential key: surprise");
}

#[test]
fn a_password_too_weak_to_be_meant_is_refused() {
    for password in ["", "short", "         "] {
        assert_eq!(
            OperatorCredentials::new(Some("owner"), Some(password), None, None).unwrap_err().0,
            "panel_password must be at least 12 characters"
        );
    }
}

#[test]
fn a_username_must_be_a_safe_name() {
    assert_eq!(
        OperatorCredentials::new(Some("owner; rm -rf /"), Some("a-long-password"), None, None).unwrap_err().0,
        "panel_username must be a safe name"
    );
}

#[test]
fn the_configuration_never_carries_a_credential() {
    let dir = TempDir::new();
    let target = dir.0.join("install.toml");
    std::fs::write(&target, "schema = 1\n").unwrap();
    write_credentials(&target, &owner("a-long-enough-password")).unwrap();
    assert!(!std::fs::read_to_string(&target).unwrap().contains("a-long-enough-password"));
}

#[test]
fn staging_hands_the_installer_a_private_copy_it_can_find() {
    let dir = TempDir::new();
    let config = dir.0.join("install.toml");
    let root = dir.0.join("state");
    std::fs::create_dir(&root).unwrap();
    let given = owner("a-long-enough-password");
    write_credentials(&config, &given).unwrap();
    let staged = stage_credentials(&root, &config).unwrap().unwrap();
    assert_eq!(mode(&staged), 0o600);
    assert_eq!(mode(staged.parent().unwrap()), 0o700);
    assert_eq!(staged_credentials(&root).unwrap(), Some(given));
}

#[test]
fn nothing_is_staged_when_the_operator_chose_generated_credentials() {
    let dir = TempDir::new();
    let root = dir.0.join("state");
    std::fs::create_dir(&root).unwrap();
    assert_eq!(stage_credentials(&root, &dir.0.join("install.toml")).unwrap(), None);
    assert_eq!(staged_credentials(&root).unwrap(), None);
}

#[test]
fn discarding_staged_credentials_leaves_nothing_behind() {
    let dir = TempDir::new();
    let config = dir.0.join("install.toml");
    let root = dir.0.join("state");
    std::fs::create_dir(&root).unwrap();
    write_credentials(&config, &owner("a-long-password")).unwrap();
    let staged = stage_credentials(&root, &config).unwrap().unwrap();
    discard_staged_credentials(&root).unwrap();
    assert!(!staged.exists());
    assert_eq!(staged_credentials(&root).unwrap(), None);
    discard_staged_credentials(&root).unwrap();
}

#[test]
fn file_bytes_match_python_and_control_characters_stay_readable() {
    let dir = TempDir::new();
    let target = dir.0.join("install.toml");
    let path = write_credentials(&target, &owner("quote\"back\\slash-x")).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "# Written by the Proxy Control wizard. Anyone who can read this file\n\
         # can sign in to the panels it describes. Delete it once the\n\
         # installation has finished.\n\
         panel_username = \"owner\"\n\
         panel_password = \"quote\\\"back\\\\slash-x\"\n"
    );
    // Python wrote U+0001 raw and could not read its own file back.
    let given = owner("tab\there\u{1}control");
    write_credentials(&target, &given).unwrap();
    assert_eq!(read_credentials(&target).unwrap(), Some(given));
}
