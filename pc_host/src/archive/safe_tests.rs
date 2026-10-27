//! Ports of `tests/test_installer_release.py` (tar, manifest, artifact cases) and
//! `tests/test_release_zip.py`; names follow the Python tests without `test_`.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::hooks;
use super::*;
use crate::archive::release::{verify_artifact, ReleaseManifest};
use crate::fs::sha256_hex;
use crate::testarchive::{tar_gz, zip_bytes, TarSpec, ZipSpec};
use crate::testutil::TempDir;

fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relative)
}

fn write_tar(dir: &Path, name: &str, members: &[TarSpec]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, tar_gz(members)).unwrap();
    path
}

fn valid_members() -> Vec<TarSpec> {
    vec![
        TarSpec::dir("pkg"),
        TarSpec::file("pkg/app", b"verified payload\n").with_mode(0o755),
        TarSpec::symlink("pkg/current", "app"),
    ]
}

fn manifest(entries: Vec<ArchiveEntry>, max_entries: u64, max_total_size: u64) -> ArchiveManifest {
    let mut manifest = ArchiveManifest::new(entries, &"0".repeat(64));
    manifest.max_entries = max_entries;
    manifest.max_total_size = max_total_size;
    manifest
}

fn valid_archive_manifest() -> ArchiveManifest {
    manifest(
        vec![
            ArchiveEntry::directory("pkg", Some(0o755)),
            ArchiveEntry::file("pkg/app", Some(0o755), Some(&sha256_hex(b"verified payload\n"))),
            ArchiveEntry::symlink("pkg/current", Some(0o777), "app"),
        ],
        16,
        1024,
    )
}

/// The Python tests' wrapper: a manifest digest of all zeros means "the archive's own digest".
fn extract(archive: &Path, destination: &Path, manifest: &ArchiveManifest) -> std::result::Result<(), String> {
    let mut manifest = manifest.clone();
    if manifest.archive_sha256 == "0".repeat(64) {
        manifest.archive_sha256 = sha256_hex(&fs::read(archive).unwrap());
    }
    safe_extract_tar(archive, destination, &manifest).map_err(|e| e.0)
}

fn stage_paths(destination: &Path) -> Vec<PathBuf> {
    let prefix = format!(".{}.stage-", destination.file_name().unwrap().to_string_lossy());
    fs::read_dir(destination.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect()
}

fn backups(parent: &Path, name: &str) -> Vec<PathBuf> {
    let prefix = format!(".{name}.backup-");
    fs::read_dir(parent)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect()
}

fn contains(error: &str, needle: &str) {
    assert!(error.contains(needle), "{error:?} does not contain {needle:?}");
}

struct HookGuard;

impl Drop for HookGuard {
    fn drop(&mut self) {
        hooks::clear();
    }
}

fn with_hook(hook: impl FnMut(Hook, &str) -> std::result::Result<(), HookFailure> + 'static) -> HookGuard {
    hooks::set(hook);
    HookGuard
}

// ----------------------------------------------------------------------------------------------
// Manifest

fn manifest_bytes(mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut data: Value =
        serde_json::from_slice(&fs::read(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap()).unwrap();
    mutate(&mut data);
    serde_json::to_vec(&data).unwrap()
}

#[test]
fn reviewed_manifest_and_historical_fixture_are_strictly_valid() {
    // Parser fixtures are historical inputs, not another source of current release defaults.
    for path in ["release/external-artifacts.json", "tests/fixtures/releases/valid-manifest.json"] {
        let bytes = fs::read(repo_file(path)).unwrap();
        assert_eq!(ReleaseManifest::from_bytes(&bytes).unwrap().schema_version, 1);
    }
}

#[test]
fn external_artifact_is_arch_specific_and_version_pinned() {
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap())
            .unwrap();
    let pin = manifest.external_artifact("three_xui", "amd64").unwrap();
    assert_eq!(pin.version, "3.10.2");
    assert_eq!(pin.tag, "v3.10.2");
    assert_eq!(pin.sha256, "bfda7921984e7a72555c38d4e861c7a8b67b3686b658608937de99682f1452d0");
    assert_eq!(pin.url, "https://github.com/MHSanaei/3x-ui/releases/download/v3.10.2/x-ui-linux-amd64.tar.gz");
    assert_eq!(pin.architecture, "amd64");
    assert_eq!(pin.spdx_license, "GPL-3.0-only");
}

#[test]
fn an_architecture_this_release_does_not_build_for_is_refused() {
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest.external_artifact("three_xui", "arm64").unwrap_err().0, "unsupported architecture: arm64");
}

#[test]
fn mita_pins_include_package_and_executable_hashes() {
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap())
            .unwrap();
    let pin = manifest.external_artifact("mita", "amd64").unwrap();
    assert_eq!(pin.version, "3.38.1");
    assert_eq!(pin.sha256, "2c7c0be33d34cf126187d97c17484a34b5c62b764c96b0a88ec4cbc7660d72c9");
    assert_eq!(pin.executable_path.as_deref(), Some("usr/bin/mita"));
    assert_eq!(
        pin.executable_sha256.as_deref(),
        Some("991179df309924d86251fa9b8109d67dc178d4161f0b83e4a5092940a79aa207")
    );
    assert_eq!(pin.spdx_license, "GPL-3.0-or-later");
    assert!(pin.url.ends_with("mita_3.38.1_amd64.deb"));
    assert!(pin.url.contains("/download/v3.38.1/"));
}

#[test]
fn manifest_rejects_invalid_schema() {
    fn pin(data: &mut Value) -> &mut Value {
        &mut data["artifacts"][0]["platforms"]["amd64"]
    }
    fn url(data: &mut Value, value: &str) {
        pin(data)["url"] = Value::from(value);
    }
    type Mutator = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Mutator, &str)> = vec![
        ("root unknown key", Box::new(|d| d["unexpected"] = true.into()), "unknown manifest key"),
        ("artifact unknown key", Box::new(|d| d["artifacts"][0]["unexpected"] = true.into()), "unknown artifact key"),
        ("pin unknown key", Box::new(move |d| pin(d)["unexpected"] = true.into()), "unknown platform key"),
        ("unsupported schema", Box::new(|d| d["schema_version"] = 2.into()), "schema_version"),
        ("uppercase digest", Box::new(move |d| pin(d)["sha256"] = "A".repeat(64).into()), "lowercase SHA-256"),
        (
            "http URL",
            Box::new(move |d| url(d, "http://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb")),
            "HTTPS",
        ),
        (
            "wrong host",
            Box::new(move |d| {
                url(d, "https://example.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb")
            }),
            "GitHub host",
        ),
        (
            "mutable latest URL",
            Box::new(move |d| url(d, "https://github.com/enfein/mieru/releases/latest/download/mita_3.38.1_amd64.deb")),
            "immutable release URL",
        ),
        (
            "URL query",
            Box::new(move |d| {
                url(d, "https://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb?raw=1")
            }),
            "query or fragment",
        ),
        ("tag version mismatch", Box::new(|d| d["artifacts"][0]["tag"] = "v3.35.0".into()), "tag must equal"),
        (
            "URL repository mismatch",
            Box::new(move |d| {
                url(d, "https://github.com/attacker/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb")
            }),
            "repository",
        ),
        ("platform mismatch", Box::new(move |d| pin(d)["architecture"] = "arm64".into()), "platform mismatch"),
        (
            "filename architecture mismatch",
            Box::new(move |d| {
                url(d, "https://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_arm64.deb")
            }),
            "architecture",
        ),
        ("unsupported SPDX", Box::new(|d| d["artifacts"][0]["spdx_license"] = "GPLv3+".into()), "SPDX"),
        (
            "missing platform",
            Box::new(|d| {
                d["artifacts"][0]["platforms"].as_object_mut().unwrap().remove("amd64");
            }),
            "platforms must be exactly",
        ),
        (
            "an unbuilt platform",
            Box::new(|d| {
                let copy = d["artifacts"][0]["platforms"]["amd64"].clone();
                d["artifacts"][0]["platforms"]["arm64"] = copy;
            }),
            "platforms must be exactly",
        ),
    ];
    for (description, mutate, needle) in cases {
        let error = ReleaseManifest::from_bytes(&manifest_bytes(mutate)).unwrap_err().0;
        assert!(error.contains(needle), "{description}: {error:?} lacks {needle:?}");
    }
}

#[test]
fn manifest_rejects_duplicate_json_keys_and_artifact_names() {
    let fixture = fs::read_to_string(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap();
    let duplicate = fixture.replacen("\"schema_version\": 1,", "\"schema_version\": 1, \"schema_version\": 1,", 1);
    assert_eq!(ReleaseManifest::from_bytes(duplicate.as_bytes()).unwrap_err().0, "duplicate JSON key: schema_version");
    let duplicate_artifact = manifest_bytes(|d| {
        let first = d["artifacts"][0].clone();
        d["artifacts"].as_array_mut().unwrap().push(first);
    });
    contains(&ReleaseManifest::from_bytes(&duplicate_artifact).unwrap_err().0, "duplicate artifact");
}

#[test]
fn manifest_rejects_constants_and_bad_text() {
    assert_eq!(
        ReleaseManifest::from_bytes(b"{\"schema_version\": NaN}").unwrap_err().0,
        "manifest must be valid UTF-8 JSON"
    );
    assert_eq!(ReleaseManifest::from_bytes(b"\xff").unwrap_err().0, "manifest must be valid UTF-8 JSON");
    assert_eq!(ReleaseManifest::from_bytes(b"[]").unwrap_err().0, "manifest must be an object");
    assert_eq!(ReleaseManifest::from_bytes(b"{}").unwrap_err().0, "missing manifest key: artifacts");
    assert_eq!(
        ReleaseManifest::from_bytes(b"{\"schema_version\": true, \"artifacts\": []}").unwrap_err().0,
        "schema_version must be the integer 1"
    );
    assert_eq!(
        ReleaseManifest::from_bytes(b"{\"schema_version\": 1, \"artifacts\": []}").unwrap_err().0,
        "artifacts must be a non-empty array"
    );
}

#[test]
fn manifest_lookup_rejects_unknown_artifact_and_architecture() {
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(repo_file("tests/fixtures/releases/valid-manifest.json")).unwrap())
            .unwrap();
    contains(&manifest.external_artifact("unknown", "amd64").unwrap_err().0, "unknown artifact");
    contains(&manifest.external_artifact("mita", "386").unwrap_err().0, "unsupported architecture");
}

#[test]
fn manifest_rejects_noncanonical_or_control_bearing_url() {
    let good = "https://github.com/enfein/mieru/releases/download/v3.38.1/mita_3.38.1_amd64.deb";
    for url in [format!(" {good}"), format!("{good} "), format!("{good}\n"), good.replacen("https", "HTTPS", 1)] {
        let data = manifest_bytes(|d| d["artifacts"][0]["platforms"]["amd64"]["url"] = url.clone().into());
        let error = ReleaseManifest::from_bytes(&data).unwrap_err().0;
        assert!(["canonical", "whitespace", "control"].iter().any(|n| error.contains(n)), "{url:?}: {error}");
    }
}

#[test]
fn the_release_manifest_pins_x86_64_only() {
    assert_eq!(crate::archive::SUPPORTED_ARCHITECTURES, ["amd64"]);
}

#[test]
fn verify_artifact_streams_and_compares_an_exact_lowercase_digest() {
    let dir = TempDir::new("verify");
    let artifact = dir.path().join("large.bin");
    let mut data = b"0123456789abcdef".repeat(200_000);
    data.extend_from_slice(b"tail");
    fs::write(&artifact, &data).unwrap();
    let digest = sha256_hex(&data);
    verify_artifact(&artifact, &digest).unwrap();
    contains(&verify_artifact(&artifact, &"0".repeat(64)).unwrap_err().0, "digest mismatch");
    contains(&verify_artifact(&artifact, &digest.to_uppercase()).unwrap_err().0, "lowercase SHA-256");
    contains(&verify_artifact(&dir.path().join("missing"), &digest).unwrap_err().0, "regular file");
    let link = dir.path().join("link");
    symlink(&artifact, &link).unwrap();
    contains(&verify_artifact(&link, &digest).unwrap_err().0, "regular file");
}

// ----------------------------------------------------------------------------------------------
// Tar extraction

#[test]
fn safe_extract_rejects_escaping_member() {
    for member in ["/etc/shadow", "../../root/.ssh", "safe/../escape"] {
        let dir = TempDir::new("escape");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &[TarSpec::file(member, b"hostile")]);
        let destination = dir.path().join("stage");
        let manifest = manifest(vec![ArchiveEntry::file("safe", None, None)], 4, 1024);
        contains(&extract(&archive, &destination, &manifest).unwrap_err(), "unsafe archive path");
        assert!(!destination.exists());
        assert!(stage_paths(&destination).is_empty());
    }
}

#[test]
fn safe_extract_rejects_backslash_member_paths() {
    for member in ["..\\\\escape", "safe\\\\..\\\\escape"] {
        let dir = TempDir::new("backslash");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &[TarSpec::file(member, b"hostile")]);
        contains(
            &extract(&archive, &dir.path().join("stage"), &valid_archive_manifest()).unwrap_err(),
            "unsafe archive path",
        );
    }
}

#[test]
fn safe_extract_rejects_escaping_symlink_target() {
    for target in ["/etc/shadow", "../../outside"] {
        let dir = TempDir::new("symlink-target");
        let mut members = valid_members();
        members[2] = TarSpec::symlink("pkg/current", target);
        let archive = write_tar(dir.path(), "artifact.tar.gz", &members);
        let destination = dir.path().join("stage");
        contains(&extract(&archive, &destination, &valid_archive_manifest()).unwrap_err(), "unsafe symlink target");
        assert!(!destination.exists());
        assert!(stage_paths(&destination).is_empty());
    }
}

#[test]
fn safe_extract_rejects_hardlinks_and_special_files() {
    // Hard link, character and block device, FIFO, an unknown type.
    for kind in *b"1346s" {
        let dir = TempDir::new("special");
        let member = TarSpec::file("pkg/app", b"").with_kind(kind).with_link("target");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &[member]);
        let manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 2, 1024);
        contains(
            &extract(&archive, &dir.path().join("stage"), &manifest).unwrap_err(),
            "unsupported archive entry type",
        );
    }
}

#[test]
fn safe_extract_rejects_setuid_and_setgid_modes() {
    for mode in [0o4755, 0o2755, 0o6755] {
        let dir = TempDir::new("setuid");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &[TarSpec::file("pkg/app", b"x").with_mode(mode)]);
        let manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 2, 1024);
        contains(&extract(&archive, &dir.path().join("stage"), &manifest).unwrap_err(), "setuid or setgid");
    }
}

#[test]
fn safe_extract_rejects_invalid_layout() {
    let cases: Vec<(Vec<TarSpec>, ArchiveManifest, &str)> = vec![
        (
            vec![TarSpec::file("pkg/app", b"one"), TarSpec::file("./pkg/app", b"two")],
            manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024),
            "duplicate normalized archive path",
        ),
        (
            vec![TarSpec::file("pkg/app", b"x"), TarSpec::file("pkg/extra", b"x")],
            manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024),
            "unexpected archive entry",
        ),
        (
            vec![TarSpec::file("pkg/app", b"x")],
            manifest(
                vec![ArchiveEntry::file("pkg/app", None, None), ArchiveEntry::file("pkg/required", None, None)],
                4,
                1024,
            ),
            "missing archive entry",
        ),
        (
            vec![TarSpec::dir("pkg/app")],
            manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024),
            "archive entry type mismatch",
        ),
        (
            vec![TarSpec::file("pkg/app", b"0123456789")],
            manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 4),
            "archive size limit",
        ),
        (
            vec![TarSpec::file("pkg/a", b"a"), TarSpec::file("pkg/b", b"b")],
            manifest(vec![ArchiveEntry::file("pkg/a", None, None), ArchiveEntry::file("pkg/b", None, None)], 1, 1024),
            "archive entry count limit",
        ),
        (
            vec![TarSpec::symlink("pkg/link", "app"), TarSpec::file("pkg/link/child", b"hostile")],
            manifest(
                vec![ArchiveEntry::symlink("pkg/link", None, "app"), ArchiveEntry::file("pkg/link/child", None, None)],
                4,
                1024,
            ),
            "non-directory parent",
        ),
    ];
    for (members, manifest, needle) in cases {
        let dir = TempDir::new("layout");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &members);
        let destination = dir.path().join("stage");
        contains(&extract(&archive, &destination, &manifest).unwrap_err(), needle);
        assert!(!destination.exists());
        assert!(stage_paths(&destination).is_empty());
    }
}

#[test]
fn safe_extract_rejects_manifest_content_and_mode_mismatch() {
    let dir = TempDir::new("mismatch");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let entries = |mode: u32| {
        manifest(
            vec![
                ArchiveEntry::directory("pkg", Some(0o755)),
                ArchiveEntry::file("pkg/app", Some(mode), Some(&"0".repeat(64))),
                ArchiveEntry::symlink("pkg/current", Some(0o777), "app"),
            ],
            16,
            1024,
        )
    };
    contains(
        &extract(&archive, &dir.path().join("stage"), &entries(0o644)).unwrap_err(),
        "archive entry mode mismatch",
    );
    contains(
        &extract(&archive, &dir.path().join("stage"), &entries(0o755)).unwrap_err(),
        "archive member digest mismatch",
    );
}

#[test]
fn safe_extract_rejects_symlinked_destination_parent() {
    let dir = TempDir::new("linked-parent");
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let linked = dir.path().join("linked");
    symlink(&outside, &linked).unwrap();
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let error = extract(&archive, &linked.join("stage"), &valid_archive_manifest()).unwrap_err();
    assert!(error.starts_with("destination parent") && error.contains("symlink"), "{error}");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn safe_extract_rejects_preexisting_destination_symlink() {
    let dir = TempDir::new("dest-link");
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("marker"), "trusted").unwrap();
    let destination = dir.path().join("stage");
    symlink(&outside, &destination).unwrap();
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    contains(
        &extract(&archive, &destination, &valid_archive_manifest()).unwrap_err(),
        "destination must not be a symlink",
    );
    assert_eq!(fs::read_to_string(outside.join("marker")).unwrap(), "trusted");
    assert!(fs::symlink_metadata(&destination).unwrap().file_type().is_symlink());
    assert!(stage_paths(&destination).is_empty());
}

#[test]
fn validation_failure_preserves_existing_destination_without_partial_tree() {
    let dir = TempDir::new("preserve");
    let destination = dir.path().join("stage");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("trusted"), "old tree").unwrap();
    let archive = write_tar(dir.path(), "artifact.tar.gz", &[TarSpec::file("unexpected", b"hostile")]);
    contains(&extract(&archive, &destination, &valid_archive_manifest()).unwrap_err(), "unexpected archive entry");
    assert_eq!(fs::read_to_string(destination.join("trusted")).unwrap(), "old tree");
    assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    assert!(stage_paths(&destination).is_empty());
}

#[test]
fn valid_extraction_replaces_preexisting_hostile_entries_without_following_them() {
    let dir = TempDir::new("hostile");
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("marker"), "outside").unwrap();
    let destination = dir.path().join("stage");
    fs::create_dir(&destination).unwrap();
    symlink(&outside, destination.join("pkg")).unwrap();
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    extract(&archive, &destination, &valid_archive_manifest()).unwrap();
    assert_eq!(fs::read_to_string(outside.join("marker")).unwrap(), "outside");
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"verified payload\n");
    assert_eq!(fs::read_link(destination.join("pkg/current")).unwrap(), PathBuf::from("app"));
    assert_eq!(fs::read(destination.join("pkg/current")).unwrap(), b"verified payload\n");
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(destination.join("pkg/app")).unwrap();
    assert_eq!(metadata.uid(), unsafe { libc::getuid() });
    assert_ne!(metadata.gid(), 43210);
    assert_eq!(metadata.mode() & 0o7777, 0o755);
    assert_eq!(fs::metadata(destination.join("pkg")).unwrap().mode() & 0o7777, 0o755);
    assert!(stage_paths(&destination).is_empty());
    assert!(backups(dir.path(), "stage").is_empty());
}

#[test]
fn extraction_failure_cleans_stage_and_preserves_existing_destination() {
    let dir = TempDir::new("copy-fails");
    let destination = dir.path().join("stage");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("trusted"), "old tree").unwrap();
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let _guard = with_hook(|point, _| match point {
        Hook::CopyMember => Err(HookFailure::Io(std::io::Error::other("simulated write failure"))),
        _ => Ok(()),
    });
    contains(&extract(&archive, &destination, &valid_archive_manifest()).unwrap_err(), "could not extract archive");
    assert_eq!(fs::read_to_string(destination.join("trusted")).unwrap(), "old tree");
    assert!(stage_paths(&destination).is_empty());
}

#[test]
fn archive_path_swap_cannot_change_verified_bytes() {
    let dir = TempDir::new("swap");
    let archive = write_tar(dir.path(), "reviewed.tar.gz", &[TarSpec::file("pkg/app", b"reviewed")]);
    let replacement = write_tar(dir.path(), "substituted.tar.gz", &[TarSpec::file("pkg/app", b"substituted")]);
    let mut manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024);
    manifest.archive_sha256 = sha256_hex(&fs::read(&archive).unwrap());
    manifest.max_decompressed_size = 32 * 1024;
    manifest.max_metadata_size = 1024;
    let (from, to) = (replacement.clone(), archive.clone());
    let swapped = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = swapped.clone();
    let _guard = with_hook(move |point, _| {
        if point == Hook::AfterVerifiedCopy {
            fs::rename(&from, &to).unwrap();
            flag.set(true);
        }
        Ok(())
    });
    let destination = dir.path().join("stage");
    safe_extract_tar(&archive, &destination, &manifest).unwrap();
    assert!(swapped.get());
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"reviewed");
}

#[test]
fn archive_digest_is_verified_before_tar_processing() {
    let dir = TempDir::new("digest-first");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &[TarSpec::file("pkg/app", b"payload")]);
    let mut manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024);
    manifest.max_decompressed_size = 32 * 1024;
    manifest.max_metadata_size = 1024;
    let destination = dir.path().join("stage");
    contains(&safe_extract_tar(&archive, &destination, &manifest).unwrap_err().0, "archive digest mismatch");
    assert!(!destination.exists());
}

#[test]
fn destination_parent_swap_is_detected_at_mutation_boundary() {
    let dir = TempDir::new("parent-swap");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let parent = dir.path().join("parent");
    fs::create_dir(&parent).unwrap();
    let destination = parent.join("stage");
    let displaced = dir.path().join("displaced-parent");
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let mut manifest = valid_archive_manifest();
    manifest.archive_sha256 = sha256_hex(&fs::read(&archive).unwrap());
    let (p, d, o) = (parent.clone(), displaced.clone(), outside.clone());
    let _guard = with_hook(move |point, _| {
        if point == Hook::AfterAnchor {
            fs::rename(&p, &d).unwrap();
            symlink(&o, &p).unwrap();
        }
        Ok(())
    });
    contains(&safe_extract_tar(&archive, &destination, &manifest).unwrap_err().0, "destination parent changed");
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&displaced).unwrap().count(), 0);
}

#[test]
fn decompressed_tar_and_extension_metadata_are_bounded() {
    let dir = TempDir::new("bounds");
    let large = write_tar(dir.path(), "large.tar.gz", &[TarSpec::file("pkg/app", &[b'x'; 4096])]);
    let mut large_manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 8192);
    large_manifest.archive_sha256 = sha256_hex(&fs::read(&large).unwrap());
    large_manifest.max_decompressed_size = 1024;
    large_manifest.max_metadata_size = 128;
    contains(
        &safe_extract_tar(&large, &dir.path().join("large-stage"), &large_manifest).unwrap_err().0,
        "decompressed archive size limit",
    );

    let long_name = format!("pkg/{}", "a".repeat(600));
    let bomb = write_tar(dir.path(), "extension.tar.gz", &[TarSpec::file(&long_name, b"x")]);
    let mut bomb_manifest = manifest(vec![ArchiveEntry::file(&long_name, None, None)], 4, 1024);
    bomb_manifest.archive_sha256 = sha256_hex(&fs::read(&bomb).unwrap());
    bomb_manifest.max_decompressed_size = 32 * 1024;
    bomb_manifest.max_metadata_size = 128;
    contains(
        &safe_extract_tar(&bomb, &dir.path().join("extension-stage"), &bomb_manifest).unwrap_err().0,
        "tar metadata limit",
    );
    // Within the bound a long (pax) name is honoured (components under NAME_MAX).
    let long_name = format!("pkg/{}/{}", "a".repeat(200), "b".repeat(200));
    let long = write_tar(dir.path(), "long.tar.gz", &[TarSpec::file(&long_name, b"x")]);
    let mut long_manifest = manifest(vec![ArchiveEntry::file(&long_name, None, None)], 4, 1024);
    long_manifest.archive_sha256 = sha256_hex(&fs::read(&long).unwrap());
    safe_extract_tar(&long, &dir.path().join("long-stage"), &long_manifest).unwrap();
    assert_eq!(fs::read(dir.path().join("long-stage").join(&long_name)).unwrap(), b"x");
}

#[test]
fn payload_bearing_nonregular_tar_entry_is_rejected() {
    let dir = TempDir::new("payload-dir");
    let mut member = TarSpec::dir("pkg");
    member.data = b"data".to_vec();
    let archive = write_tar(dir.path(), "payload-directory.tar.gz", &[member]);
    let mut manifest = manifest(vec![ArchiveEntry::directory("pkg", Some(0o755))], 4, 1024);
    manifest.max_decompressed_size = 32 * 1024;
    manifest.max_metadata_size = 1024;
    contains(&extract(&archive, &dir.path().join("stage"), &manifest).unwrap_err(), "payload-bearing non-regular");
}

#[test]
fn backup_cleanup_failure_does_not_report_failed_install() {
    let dir = TempDir::new("backup-cleanup");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let destination = dir.path().join("stage");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("old"), "trusted old tree").unwrap();
    let _guard = with_hook(|point, name| {
        if point == Hook::RemoveTree && name.contains(".backup-") {
            return Err(HookFailure::Other);
        }
        Ok(())
    });
    extract(&archive, &destination, &valid_archive_manifest()).unwrap();
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"verified payload\n");
    assert_eq!(backups(dir.path(), "stage").len(), 1);
}

#[test]
fn in_place_archive_overwrite_after_hash_cannot_change_parsed_bytes() {
    let dir = TempDir::new("overwrite");
    let archive = write_tar(dir.path(), "reviewed-inode.tar.gz", &[TarSpec::file("pkg/app", b"reviewed")]);
    let replacement = tar_gz(&[TarSpec::file("pkg/app", b"substituted")]);
    let mut manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024);
    manifest.archive_sha256 = sha256_hex(&fs::read(&archive).unwrap());
    let target = archive.clone();
    let _guard = with_hook(move |point, _| {
        if point == Hook::AfterVerifiedCopy {
            fs::write(&target, &replacement).unwrap();
        }
        Ok(())
    });
    let destination = dir.path().join("stage");
    safe_extract_tar(&archive, &destination, &manifest).unwrap();
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"reviewed");
}

#[test]
fn compressed_archive_bytes_have_a_hard_bound() {
    let dir = TempDir::new("compressed");
    let noise: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let archive = write_tar(dir.path(), "compressed-limit.tar.gz", &[TarSpec::file("pkg/app", &noise)]);
    let mut manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 8192);
    manifest.archive_sha256 = sha256_hex(&fs::read(&archive).unwrap());
    manifest.max_compressed_size = 64;
    contains(
        &safe_extract_tar(&archive, &dir.path().join("stage"), &manifest).unwrap_err().0,
        "compressed archive size limit",
    );
}

#[test]
fn untrusted_immediate_destination_parent_is_rejected() {
    for mode in [0o777, 0o1777] {
        let dir = TempDir::new("untrusted-parent");
        let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
        let parent = dir.path().join("untrusted-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        contains(
            &extract(&archive, &parent.join("stage"), &valid_archive_manifest()).unwrap_err(),
            "untrusted destination parent",
        );
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
}

#[test]
fn nonsticky_writable_destination_ancestor_is_rejected() {
    let dir = TempDir::new("untrusted-ancestor");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let ancestor = dir.path().join("untrusted-ancestor");
    fs::create_dir(&ancestor).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).unwrap();
    let parent = ancestor.join("trusted-child");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    contains(
        &extract(&archive, &parent.join("stage"), &valid_archive_manifest()).unwrap_err(),
        "untrusted destination ancestor",
    );
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
}

#[test]
fn sticky_writable_ancestor_allows_trusted_owned_child() {
    let dir = TempDir::new("sticky");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let sticky = dir.path().join("sticky-ancestor");
    fs::create_dir(&sticky).unwrap();
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();
    let parent = sticky.join("trusted-child");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let destination = parent.join("stage");
    extract(&archive, &destination, &valid_archive_manifest()).unwrap();
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"verified payload\n");
}

#[test]
fn old_tree_cleanup_is_iterative_for_attacker_depth() {
    let dir = TempDir::new("deep");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let destination = dir.path().join("stage");
    fs::create_dir(&destination).unwrap();
    // 300 levels, as in Python (there under a recursion limit of 200): deeper than PATH_MAX
    // allows a path-walking removal to name the leaves.
    let mut fd = dirfd::open_path(destination.as_os_str().as_bytes()).unwrap();
    for _ in 0..300 {
        dirfd::mkdir_at(fd.as_raw_fd(), b"d", 0o700).unwrap();
        fd = dirfd::open_dir_at(fd.as_raw_fd(), b"d").unwrap();
    }
    drop(fd);
    extract(&archive, &destination, &valid_archive_manifest()).unwrap();
    assert_eq!(fs::read(destination.join("pkg/app")).unwrap(), b"verified payload\n");
    assert!(backups(dir.path(), "stage").is_empty());
}

#[test]
fn precommit_cleanup_failure_does_not_mask_primary_error() {
    let dir = TempDir::new("primary");
    let archive = write_tar(dir.path(), "artifact.tar.gz", &valid_members());
    let destination = dir.path().join("stage");
    let _guard = with_hook(|point, _| match point {
        Hook::CopyMember => Err(HookFailure::Release(ReleaseError::new("primary extraction failure"))),
        Hook::RemoveTree => Err(HookFailure::Other),
        _ => Ok(()),
    });
    contains(&extract(&archive, &destination, &valid_archive_manifest()).unwrap_err(), "primary extraction failure");
    assert_eq!(stage_paths(&destination).len(), 1);
}

#[test]
fn raw_scan_refuses_base256_sizes_and_missing_terminators() {
    let dir = TempDir::new("raw-scan");
    let mut tar = crate::testarchive::tar_bytes(&[TarSpec::file("pkg/app", b"x")]);
    // Base-256 size field.
    let mut base256 = tar.clone();
    base256[124] = 0x80;
    let path = dir.path().join("a.tar");
    fs::write(&path, &base256).unwrap();
    let mut manifest = manifest(vec![ArchiveEntry::file("pkg/app", None, None)], 4, 1024);
    contains(&extract(&path, &dir.path().join("s1"), &manifest).unwrap_err(), "unsupported tar numeric encoding");
    // No zero block at all.
    tar.truncate(1024);
    fs::write(&path, &tar).unwrap();
    manifest.archive_sha256 = "0".repeat(64);
    contains(&extract(&path, &dir.path().join("s2"), &manifest).unwrap_err(), "missing a zero terminator");
    // bzip2 / xz are refused before parsing.
    fs::write(&path, b"BZh91AY&SY").unwrap();
    contains(&extract(&path, &dir.path().join("s3"), &manifest).unwrap_err(), "unsupported archive compression");
    // A plain (uncompressed) tar is accepted.
    fs::write(&path, crate::testarchive::tar_bytes(&[TarSpec::file("pkg/app", b"x")])).unwrap();
    extract(&path, &dir.path().join("s4"), &manifest).unwrap();
}

#[test]
fn manifest_itself_is_validated() {
    let dir = TempDir::new("manifest-validation");
    let archive = write_tar(dir.path(), "a.tar.gz", &valid_members());
    let check = |manifest: ArchiveManifest, needle: &str| {
        contains(&safe_extract_tar(&archive, &dir.path().join("x"), &manifest).unwrap_err().0, needle);
    };
    let mut m = valid_archive_manifest();
    m.archive_sha256 = "x".into();
    check(m, "archive must be an exact lowercase SHA-256");
    let mut m = valid_archive_manifest();
    m.max_compressed_size = 0;
    check(m, "max_compressed_size");
    let mut m = valid_archive_manifest();
    m.entries.push(ArchiveEntry::file("./pkg/app", None, None));
    check(m, "archive manifest path must be canonical: ./pkg/app");
    let mut m = valid_archive_manifest();
    m.entries.push(ArchiveEntry::file("pkg/app", None, None));
    check(m, "duplicate archive manifest path: pkg/app");
    let mut m = valid_archive_manifest();
    m.entries[0].kind = "fifo".into();
    check(m, "invalid archive manifest entry kind: fifo");
    let mut m = valid_archive_manifest();
    m.entries[0].sha256 = Some("0".repeat(64));
    check(m, "only regular files may have a member SHA-256");
    let mut m = valid_archive_manifest();
    m.entries[2].link_target = None;
    check(m, "symlink manifest entry requires a target: pkg/current");
    let mut m = valid_archive_manifest();
    m.entries[1].link_target = Some("x".into());
    check(m, "non-symlink manifest entry has a target: pkg/app");
    let mut m = valid_archive_manifest();
    m.entries.clear();
    check(m, "archive manifest entries must be a non-empty tuple");
}

// ----------------------------------------------------------------------------------------------
// Zip extraction (tests/test_release_zip.py)

fn zip_archive(dir: &Path, members: &[(&str, &[u8])], extras: bool) -> PathBuf {
    let mut specs: Vec<ZipSpec> = members.iter().map(|(name, data)| ZipSpec::file(name, data)).collect();
    if extras {
        specs.push(ZipSpec::file("README.md", b"# not extracted"));
        specs.push(ZipSpec::file("evil/../escape", b"nope"));
        specs.push(ZipSpec { name: "link".into(), data: b"/etc/passwd".to_vec(), external_mode: 0o120777 });
    }
    let path = dir.join("Xray-linux-64.zip");
    fs::write(&path, zip_bytes(&specs).0).unwrap();
    path
}

fn pins(members: &[(&str, &[u8])], modes: &[(&str, u32)]) -> Vec<(String, MemberPin)> {
    members
        .iter()
        .map(|(name, data)| {
            let mode = modes.iter().find(|(n, _)| n == name).map(|(_, m)| *m).unwrap_or(0o644);
            (name.to_string(), MemberPin { sha256: sha256_hex(data), size: data.len() as u64, mode })
        })
        .collect()
}

#[test]
fn safe_extract_zip_extracts_named_members_only() {
    let dir = TempDir::new("zip-ok");
    let mut xray = b"\x7fELF".to_vec();
    xray.extend_from_slice(crate::fs::token_hex::<32>().as_bytes());
    let members: [(&str, &[u8]); 3] = [("xray", &xray), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    let archive = zip_archive(dir.path(), &members, true);
    let destination = dir.path().join("out");
    safe_extract_zip_default(&archive, &destination, &pins(&members, &[("xray", 0o755)])).unwrap();
    let mut names: Vec<String> =
        fs::read_dir(&destination).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["geoip.dat", "geosite.dat", "xray"]);
    assert_eq!(fs::read(destination.join("xray")).unwrap(), xray);
    assert_eq!(fs::metadata(destination.join("xray")).unwrap().permissions().mode() & 0o7777, 0o755);
    assert_eq!(fs::metadata(destination.join("geoip.dat")).unwrap().permissions().mode() & 0o7777, 0o644);
    assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o7777, 0o755);
}

#[test]
fn safe_extract_zip_rejects_member_digest_mismatch() {
    let dir = TempDir::new("zip-digest");
    let members: [(&str, &[u8]); 3] = [("xray", b"binary"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    let archive = zip_archive(dir.path(), &members, true);
    let mut pins = pins(&members, &[]);
    pins[2].1 = MemberPin { sha256: "0".repeat(64), size: 7, mode: 0o644 };
    let destination = dir.path().join("out");
    contains(&safe_extract_zip_default(&archive, &destination, &pins).unwrap_err().0, "geosite.dat");
    assert!(!destination.exists());
}

#[test]
fn safe_extract_zip_rejects_oversized_and_undersized_members() {
    let dir = TempDir::new("zip-size");
    let members: [(&str, &[u8]); 3] = [("xray", b"binary"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    let archive = zip_archive(dir.path(), &members, true);
    let mut wrong = pins(&members, &[]);
    wrong[0].1 = MemberPin { sha256: sha256_hex(b"binary"), size: 3, mode: 0o755 };
    contains(&safe_extract_zip_default(&archive, &dir.path().join("out"), &wrong).unwrap_err().0, "size");
    contains(&safe_extract_zip(&archive, &dir.path().join("out"), &pins(&members, &[]), 4).unwrap_err().0, "size");
    assert!(!dir.path().join("out").exists());
}

#[test]
fn safe_extract_zip_rejects_missing_member_and_bad_names() {
    let dir = TempDir::new("zip-missing");
    let members: [(&str, &[u8]); 2] = [("xray", b"binary"), ("geoip.dat", b"geoip")];
    let archive = zip_archive(dir.path(), &members, true);
    let all: [(&str, &[u8]); 3] = [("xray", b"binary"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    contains(
        &safe_extract_zip_default(&archive, &dir.path().join("out"), &pins(&all, &[])).unwrap_err().0,
        "geosite.dat",
    );
    for bad in ["../xray", "bin/xray"] {
        let pin = vec![(bad.to_string(), MemberPin { sha256: "0".repeat(64), size: 1, mode: 0o644 })];
        contains(&safe_extract_zip_default(&archive, &dir.path().join("out"), &pin).unwrap_err().0, "member name");
    }
    // A symlink or a directory under a reviewed name is not a regular file.
    let link_pin = vec![("link".to_string(), MemberPin { sha256: sha256_hex(b"/etc/passwd"), size: 11, mode: 0o644 })];
    contains(
        &safe_extract_zip_default(&archive, &dir.path().join("out"), &link_pin).unwrap_err().0,
        "not a regular file: link",
    );
}

#[test]
fn safe_extract_zip_replaces_a_previous_install_atomically() {
    let dir = TempDir::new("zip-replace");
    let members: [(&str, &[u8]); 3] = [("xray", b"one"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    let destination = dir.path().join("out");
    safe_extract_zip_default(&zip_archive(dir.path(), &members, true), &destination, &pins(&members, &[])).unwrap();
    fs::write(destination.join("stale"), b"left over").unwrap();
    let newer: [(&str, &[u8]); 3] = [("xray", b"two"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    safe_extract_zip_default(&zip_archive(dir.path(), &newer, true), &destination, &pins(&newer, &[])).unwrap();
    assert_eq!(fs::read(destination.join("xray")).unwrap(), b"two");
    assert!(!destination.join("stale").exists());
    assert!(stage_paths(&destination).is_empty());
}

#[test]
fn safe_extract_zip_refuses_symlinked_destination() {
    let dir = TempDir::new("zip-dest-link");
    let members: [(&str, &[u8]); 3] = [("xray", b"one"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite")];
    let target = dir.path().join("elsewhere");
    fs::create_dir(&target).unwrap();
    let destination = dir.path().join("out");
    symlink(&target, &destination).unwrap();
    assert!(
        safe_extract_zip_default(&zip_archive(dir.path(), &members, true), &destination, &pins(&members, &[])).is_err()
    );
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn xray_pin_includes_archive_and_member_digests() {
    let manifest =
        ReleaseManifest::from_bytes(&fs::read(repo_file("release/external-artifacts.json")).unwrap()).unwrap();
    let pin = manifest.external_artifact("xray", "amd64").unwrap();
    assert_eq!((pin.version.as_str(), pin.tag.as_str()), ("26.10.17", "v26.10.17"));
    assert_eq!(pin.url, "https://github.com/XTLS/Xray-core/releases/download/v26.10.17/Xray-linux-64.zip");
    assert_eq!(pin.sha256, "ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158");
    assert_eq!(pin.spdx_license, "MPL-2.0");
    assert_eq!(pin.executable_path, None);
    let expected = [
        ("xray", "6771b2b2700dee175357024738ad579de1c3f2c49eec0257e737d5aa38d12fed", 34971772, 0o755),
        ("geoip.dat", "010bfc2e353c5e34e23156004944444ca260bae999e73171bdd7974056557959", 16587403, 0o644),
        ("geosite.dat", "8474140bc89940897ee2b629be8fc92f34a496bd32e45829605d17715f4340d6", 11205406, 0o644),
    ];
    assert_eq!(pin.members.as_ref().unwrap().len(), 3);
    for (name, sha, size, mode) in expected {
        assert_eq!(pin.member(name).unwrap(), &MemberPin { sha256: sha.into(), size, mode });
    }
}

#[test]
fn manifest_members_are_validated() {
    let base = fs::read_to_string(repo_file("release/external-artifacts.json")).unwrap();
    contains(
        &ReleaseManifest::from_bytes(base.replace("\"mode\": \"0755\"", "\"mode\": \"4755\"").as_bytes())
            .unwrap_err()
            .0,
        "member",
    );
    contains(
        &ReleaseManifest::from_bytes(base.replace("\"xray\": {", "\"bin/xray\": {").as_bytes()).unwrap_err().0,
        "member",
    );
    contains(
        &ReleaseManifest::from_bytes(
            base.replace("\"filename_architecture\": \"64\"", "\"filename_architecture\": \"arm\"").as_bytes(),
        )
        .unwrap_err()
        .0,
        "architecture",
    );
}

#[test]
fn zip_stream_is_read_in_bounded_chunks() {
    let dir = TempDir::new("zip-lie");
    let xray = vec![b'x'; 3000];
    let specs = [ZipSpec::file("xray", &xray), ZipSpec::file("geoip.dat", b"g"), ZipSpec::file("geosite.dat", b"s")];
    let (mut raw, central) = zip_bytes(&specs);
    // Lie about the first member's uncompressed size in the central directory (+24).
    raw[central[0] + 24..central[0] + 28].copy_from_slice(&10u32.to_le_bytes());
    let archive = dir.path().join("Xray-linux-64.zip");
    fs::write(&archive, raw).unwrap();
    let pins = vec![
        ("xray".to_string(), MemberPin { sha256: sha256_hex(&xray), size: 10, mode: 0o644 }),
        ("geoip.dat".to_string(), MemberPin { sha256: sha256_hex(b"g"), size: 1, mode: 0o644 }),
        ("geosite.dat".to_string(), MemberPin { sha256: sha256_hex(b"s"), size: 1, mode: 0o644 }),
    ];
    assert!(safe_extract_zip_default(&archive, &dir.path().join("out"), &pins).is_err());
    assert!(!dir.path().join("out").exists());
    assert!(stage_paths(&dir.path().join("out")).is_empty());
}

use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
