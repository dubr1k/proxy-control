use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::testarchive::{tar_gz, TarSpec};
use crate::testutil::TempDir;

/// `v3.3.0:version_agent/service.py` `PANEL_SYNC`.
const PANEL_SYNC_330: &[&str] = &[
    "panel",
    "installer",
    "scripts",
    "docker",
    "mieru_manager",
    "naive_manager",
    "xray_router_manager",
    "awg_manager",
    "trusttunnel_manager",
    "mcp_server",
    "release",
    "docs",
    "compose.yaml",
    "compose.naive.yaml",
    "compose.mieru.yaml",
    "compose.xray-router.yaml",
    "compose.amneziawg.yaml",
    "compose.trusttunnel.yaml",
    "compose.mcp.yaml",
    "compose.agent.yaml",
    "compose.fleet-central.yaml",
    "VERSION",
    "uninstall.sh",
    "install.sh",
    "install-bootstrap",
    "CHANGELOG.md",
    "CHANGELOG.ru.md",
    "README.md",
    "README.en.md",
    "THIRD_PARTY_NOTICES.md",
    "LICENSE",
];

fn python_names(file: &str, start: &str, end: char) -> Option<Vec<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(file);
    let text = fs::read_to_string(path).ok()?;
    let from = text.find(start)? + start.len();
    let block = &text[from..from + text[from..].find(end)?];
    Some(block.split(['\'', '"']).enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, s)| s.to_string()).collect())
}

#[test]
fn panel_sync_covers_every_synced_tree() {
    for name in PANEL_SYNC_330 {
        assert!(PANEL_SYNC.contains(name), "{name} synced by 3.3.0 agents is missing");
    }
    for name in RUST_MANAGERS.iter().chain([&"pc_common", &"pc_host", &"installer_core"]) {
        assert!(PANEL_SYNC.contains(name), "{name}");
    }
    assert_eq!(PANEL_SYNC.len(), PANEL_SYNC_330.len() + 3);
    let mut sorted = PANEL_SYNC.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), PANEL_SYNC.len(), "no duplicates");
}

#[test]
fn panel_sync_is_also_the_handoff_allow_list() {
    for name in PANEL_SYNC {
        assert!(handoff_allows(name));
    }
    for name in ["version_agent", "secrets", ".env", "version-overrides", "bin", "", "../panel"] {
        assert!(!handoff_allows(name), "{name}");
    }
}

#[test]
fn panel_sync_matches_the_python_lists_while_they_exist() {
    // Until the cutover removes them: the agent's tuple and the handoff's allow-list are the
    // Rust list without the host crates `pc_host` and `installer_core`.
    let mut ours: Vec<String> =
        PANEL_SYNC.iter().filter(|n| !["pc_host", "installer_core"].contains(*n)).map(|n| n.to_string()).collect();
    ours.sort();
    if let Some(mut agent) = python_names("version_agent/service.py", "PANEL_SYNC = (", ')') {
        agent.sort();
        assert_eq!(agent, ours);
    }
    if let Some(mut allowed) = python_names("installer/transaction.py", "allowed = {", '}') {
        allowed.sort();
        assert_eq!(allowed, ours);
    }
}

fn member(name: &str, kind: u8, size: u64) -> TarMember {
    TarMember { name: name.into(), kind_byte: kind, mode: 0o644, size, linkname: String::new(), data_offset: 0 }
}

#[test]
fn preflight_refuses_everything_outside_the_release_tree() {
    let version = member("proxy-control/VERSION", b'0', 6);
    for bad in [
        "/proxy-control/x",
        "other/x",
        "proxy-control/../x",
        "proxy-control//x",
        "proxy-control/./x",
        "./proxy-control/x",
    ] {
        let err = preflight(&[version.clone(), member(bad, b'0', 1)]).unwrap_err();
        assert_eq!(err.0, format!("panel archive: refusing member {}", py_repr(bad)));
    }
    // Symlink, hard link, devices, FIFO, GNU sparse.
    for kind in *b"21346S" {
        let err = preflight(&[version.clone(), member("proxy-control/x", kind, 0)]).unwrap_err();
        assert_eq!(err.0, "panel archive: refusing non-regular member 'proxy-control/x'");
    }
    let huge = member("proxy-control/big", b'0', MAX_PANEL_TREE);
    assert_eq!(preflight(&[version.clone(), huge]).unwrap_err().0, "panel archive: tree is too large");
    assert_eq!(
        preflight(&[member("proxy-control/README.md", b'0', 1)]).unwrap_err().0,
        "panel archive: no VERSION file"
    );
    // The top directory itself is accepted but not returned; contiguous files are regular.
    let accepted = preflight(&[member("proxy-control", b'5', 0), version, member("proxy-control/a", b'7', 1)]).unwrap();
    assert_eq!(accepted.iter().map(|m| m.relative()).collect::<Vec<_>>(), ["VERSION", "a"]);
}

#[test]
fn extracts_files_directories_and_modes() {
    let dir = TempDir::new("panel");
    let long = format!("proxy-control/docs/{}.md", "n".repeat(120));
    let payload = tar_gz(&[
        TarSpec::dir("proxy-control"),
        TarSpec::file("proxy-control/VERSION", b"4.0.0\n"),
        TarSpec::dir("proxy-control/installer/bin/linux-amd64"),
        TarSpec::file("proxy-control/installer/bin/linux-amd64/proxy-control-installer", b"\x7fELF").with_mode(0o755),
        TarSpec::file("proxy-control/zero-mode", b"z").with_mode(0),
        TarSpec::file(&long, b"long name"),
    ]);
    let staging = dir.path().join("staging");
    extract_panel_archive(&payload, &staging).unwrap();
    assert_eq!(fs::read(staging.join("VERSION")).unwrap(), b"4.0.0\n");
    let binary = staging.join("installer/bin/linux-amd64/proxy-control-installer");
    assert_eq!(fs::metadata(&binary).unwrap().permissions().mode() & 0o7777, 0o755);
    assert_eq!(fs::metadata(staging.join("zero-mode")).unwrap().permissions().mode() & 0o7777, 0o644);
    assert_eq!(fs::read(staging.join(&long["proxy-control/".len()..])).unwrap(), b"long name");
    // The staging directory must not exist yet.
    assert!(extract_panel_archive(&payload, &staging).is_err());
}

#[test]
fn archive_errors_name_the_problem() {
    let dir = TempDir::new("panel-errors");
    assert_eq!(
        extract_panel_archive(b"PK\x03\x04", &dir.path().join("a")).unwrap_err().0,
        "panel archive is not a tar.gz: not a gzip file"
    );
    let bad = tar_gz(&[TarSpec::file("proxy-control/VERSION", b"1"), TarSpec::symlink("proxy-control/link", "/etc")]);
    assert_eq!(
        extract_panel_archive(&bad, &dir.path().join("b")).unwrap_err().0,
        "panel archive: refusing non-regular member 'proxy-control/link'"
    );
    let raw = crate::testarchive::tar_bytes(&[TarSpec::file("proxy-control/VERSION", &[b'1'; 2000])]);
    let truncated = crate::testarchive::gzip(&raw[..1024]);
    let err = extract_panel_archive(&truncated, &dir.path().join("c")).unwrap_err().0;
    assert!(err.starts_with("panel archive is not a tar.gz: "), "{err}");
    assert!(!dir.path().join("b").exists());
}

#[test]
fn panel_preflight_refuses_an_unsafe_archive_before_touching_anything() {
    // tests/test_version_agent_panel.py, the archive half (the agent half is WP7).
    let dir = TempDir::new("panel-unsafe");
    let cases = [
        tar_gz(&[
            TarSpec::file("proxy-control/VERSION", b"x\n"),
            TarSpec::file("proxy-control/../etc/cron.d/x", b"* * * * * root id\n"),
        ]),
        tar_gz(&[TarSpec::file("proxy-control/VERSION", b"x\n"), TarSpec::file("/etc/passwd", b"root::0:0\n")]),
        tar_gz(&[TarSpec::file("proxy-control/VERSION", b"x\n"), TarSpec::file("other/VERSION", b"x\n")]),
        tar_gz(&[TarSpec::file("proxy-control/VERSION", b"x\n"), TarSpec::symlink("proxy-control/panel/link", "/etc")]),
        b"not a tarball".to_vec(),
    ];
    for (index, payload) in cases.iter().enumerate() {
        let staging = dir.path().join(format!("staging-{index}"));
        let err = extract_panel_archive(payload, &staging).unwrap_err();
        assert!(err.0.contains("archive"), "{err}");
        assert!(!staging.exists());
    }
}

#[test]
fn members_can_be_read_without_extracting() {
    let payload =
        tar_gz(&[TarSpec::file("proxy-control/VERSION", b"4.0.0\n"), TarSpec::file("proxy-control/b", b"bee")]);
    let mut archive = PanelArchive::open(&payload).unwrap();
    let members = archive.members().to_vec();
    assert_eq!(members.len(), 2);
    assert_eq!(archive.read(&members[1]).unwrap(), b"bee");
    assert_eq!(archive.read(&members[0]).unwrap(), b"4.0.0\n");
}
