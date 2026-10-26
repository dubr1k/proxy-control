use serde_json::json;

use super::*;
use crate::testutil::TempDir;

fn golden_release() -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/host-golden/plans/release.json")).unwrap()
}

#[test]
fn reads_the_identity_build_py_stamps() {
    let identity = ReleaseIdentity::from_bytes(&golden_release()).unwrap();
    assert_eq!(identity.tag, "v3.3.0");
    assert_eq!(identity.commit, "0".repeat(40));
    assert_eq!(identity.version.as_deref(), Some("3.3.0"));
    assert_eq!(identity.components["xray"], "26.10.17");
    assert_eq!(identity.artifacts["mita:amd64"], "2c7c0be33d34cf126187d97c17484a34b5c62b764c96b0a88ec4cbc7660d72c9");
    assert!(identity.binaries.is_empty());
    assert_eq!(identity.builder, None);
    // release/build.py writes it as pretty2; the bytes survive a rewrite.
    let value = crate::json::loads(&golden_release()).unwrap();
    assert_eq!(crate::json::pretty2(&value).as_bytes(), golden_release());
}

#[test]
fn additive_4_0_keys() {
    let mut value = crate::json::loads(&golden_release()).unwrap();
    value["binaries"] = json!({
        INSTALLER_BINARY: "a".repeat(64),
        AGENT_BINARY: "b".repeat(64),
    });
    value["builder"] =
        json!({"image": "rust:1.99-alpine@sha256:x", "target": "x86_64-unknown-linux-musl", "rustc": "1.99.1"});
    value["unknown_future_key"] = json!(1);
    let identity = ReleaseIdentity::from_bytes(crate::json::pretty2(&value).as_bytes()).unwrap();
    assert_eq!(identity.binaries.len(), 2);
    assert_eq!(identity.builder.unwrap().target, "x86_64-unknown-linux-musl");
    for bad in
        [json!({"../x": "a".repeat(64)}), json!({"x": "A".repeat(64)}), json!({"/abs": "a".repeat(64)}), json!([])]
    {
        value["binaries"] = bad;
        assert_eq!(
            ReleaseIdentity::from_bytes(value.to_string().as_bytes()).unwrap_err().to_string(),
            "the release identity binaries are invalid"
        );
    }
    value["binaries"] = json!({});
    value["builder"] = json!({"image": "x"});
    assert_eq!(
        ReleaseIdentity::from_bytes(value.to_string().as_bytes()).unwrap_err().to_string(),
        "the release identity builder is invalid"
    );
}

#[test]
fn python_reader_errors_and_str_coercion() {
    assert_eq!(ReleaseIdentity::from_bytes(b"{").unwrap_err(), IdentityError::Missing);
    assert_eq!(
        ReleaseIdentity::from_bytes(b"{").unwrap_err().to_string(),
        "this tree carries no release identity; install from a built release"
    );
    assert_eq!(ReleaseIdentity::from_bytes(b"[]").unwrap_err(), IdentityError::Incomplete);
    assert_eq!(ReleaseIdentity::from_bytes(b"{\"tag\": \"v1\"}").unwrap_err(), IdentityError::Incomplete);
    let coerced = ReleaseIdentity::from_bytes(
        br#"{"tag": 1, "commit": true, "manifest_sha256": null, "components": {"a": 1.5}}"#,
    )
    .unwrap();
    assert_eq!(
        (coerced.tag.as_str(), coerced.commit.as_str(), coerced.manifest_sha256.as_str()),
        ("1", "True", "None")
    );
    assert_eq!(coerced.components["a"], "1.5");
    assert_eq!(
        ReleaseIdentity::from_bytes(br#"{"tag": "v", "commit": "c", "manifest_sha256": "m", "components": []}"#)
            .unwrap_err(),
        IdentityError::Incomplete
    );
    let dir = TempDir::new("identity");
    assert_eq!(ReleaseIdentity::read(dir.path()).unwrap_err(), IdentityError::Missing);
}

#[test]
fn binaries_are_checked_after_extraction() {
    let dir = TempDir::new("binaries");
    let path = dir.path().join(INSTALLER_BINARY);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"\x7fELF").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let mut identity = ReleaseIdentity::from_bytes(&golden_release()).unwrap();
    identity.binaries.insert(INSTALLER_BINARY.into(), crate::fs::sha256_hex(b"\x7fELF"));
    verify_binaries(dir.path(), &identity).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        verify_binaries(dir.path(), &identity).unwrap_err(),
        format!("release binary mode is not 0755: {INSTALLER_BINARY}")
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&path, b"other").unwrap();
    assert_eq!(
        verify_binaries(dir.path(), &identity).unwrap_err(),
        format!("release binary digest mismatch: {INSTALLER_BINARY}")
    );
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/bin/sh", &path).unwrap();
    assert_eq!(
        verify_binaries(dir.path(), &identity).unwrap_err(),
        format!("release binary is not a regular file: {INSTALLER_BINARY}")
    );
    fs::remove_file(&path).unwrap();
    assert!(verify_binaries(dir.path(), &identity).unwrap_err().starts_with("release binary is missing: "));
}

#[test]
fn published_manifest_describes_its_archive() {
    let document = json!({
        "archive": "proxy-control-v4.0.0.tar.gz", "archive_sha256": "a".repeat(64), "commit": "c".repeat(40),
        "external_manifest_sha256": "e".repeat(64), "file_count": 900, "schema": 1, "source_epoch": 1767225600,
        "tag": "v4.0.0", "version": "4.0.0",
    });
    let manifest = PublishedManifest::from_bytes(crate::json::pretty2(&document).as_bytes()).unwrap();
    assert_eq!(manifest.file_count, 900);
    let sha = "a".repeat(64);
    assert!(manifest.describes("proxy-control-v4.0.0.tar.gz", &sha, "4.0.0").is_ok());
    assert_eq!(manifest.describes("x.tar.gz", &sha, "4.0.0"), Err("the manifest names a different archive"));
    assert_eq!(
        manifest.describes("proxy-control-v4.0.0.tar.gz", &"b".repeat(64), "4.0.0"),
        Err("the manifest records a different archive digest")
    );
    assert_eq!(
        manifest.describes("proxy-control-v4.0.0.tar.gz", &sha, "4.0.1"),
        Err("the manifest version or tag disagrees with the requested release")
    );
    assert!(PublishedManifest::from_bytes(b"{}").is_err());
}
