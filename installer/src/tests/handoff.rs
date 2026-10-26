//! The handoff cases of `tests/test_installer_core.py` (`test_panel_handoff_*`,
//! `test_explicit_legacy_recovery_*`) and `tests/test_version_agent_panel.py`
//! (`test_panel_update_*` journal parts, `test_legacy_recovery_reconciles_exact_agent_bytes_only`),
//! driven through journals the engine wrote with the fake Core and agent adapters.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use pc_host::fs::sha256_hex;
use pc_host::TxError;

use super::fakes::{host, owned_host, replace_tree, write, OwnedHost, AGENT_CODE, PROJECT, UNIT};
use crate::error::Error;
use crate::handoff::PanelOwnershipHandoff;
use crate::journal::Status;
use crate::store::JournalFile;
use crate::testkit::TempDir;

fn make_handoff<'s>(owned: &'s OwnedHost, staged: &Path, names: &[&str], legacy: bool) -> PanelOwnershipHandoff<'s> {
    PanelOwnershipHandoff::new(owned.engine.store(), &host(&owned.root, PROJECT), staged, names, legacy, None).unwrap()
}

fn project(owned: &OwnedHost) -> std::path::PathBuf {
    host(&owned.root, PROJECT)
}

fn assert_message(result: Result<(), Error>, fragment: &str) -> Error {
    let err = result.expect_err("the handoff must refuse");
    assert!(err.message().contains(fragment), "{:?} does not mention {fragment:?}", err.message());
    err
}

fn core_digest(owned: &OwnedHost, path: &str) -> String {
    let state = owned.engine.store().read_state().unwrap();
    state.checkpoint("core.runtime").unwrap().data["ownership"][path]["sha256"].as_str().unwrap().to_string()
}

/// `_panel_archive()` of the agent tests, as an extracted staging tree.
fn panel_archive(staged: &Path, agent: &[u8]) {
    for (name, data) in [
        ("VERSION", &b"0.11.0\n"[..]),
        ("panel/app.py", b"new panel\n"),
        ("panel/static/js/app.js", b"new js\n"),
        ("compose.yaml", b"new compose\n"),
        ("scripts/tool.sh", b"#!/bin/sh\n"),
        ("naive_manager/app.py", b"changed naive\n"),
        ("mieru_manager/app.py", b"same mieru\n"),
        ("version_agent/service.py", agent),
    ] {
        write(&staged.join(name), data);
    }
}

const ARCHIVE_NAMES: &[&str] = &["panel", "scripts", "naive_manager", "mieru_manager", "compose.yaml", "VERSION"];

/// The agent's sync: every staged entry replaces its target.
fn sync(owned: &OwnedHost, staged: &Path, names: &[&str], with_agent: bool) {
    for name in names {
        replace_tree(&staged.join(name), &project(owned).join(name));
    }
    if with_agent {
        replace_tree(&staged.join("version_agent"), &host(&owned.root, AGENT_CODE));
    }
}

#[test]
fn panel_handoff_keeps_core_repair_and_uninstall_owned() {
    let dir = TempDir::new("handoff");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let old = owned.engine.store().read_state().unwrap();
    let staged = dir.path().join("staged");
    write(&staged.join("panel/app.py"), b"new panel\n");
    write(&staged.join("panel/new.py"), b"new file\n");
    write(&staged.join("docs/README.md"), b"new docs\n");
    let mut handoff = make_handoff(&owned, &staged, &["panel", "docs"], false);
    handoff.prepare().unwrap();
    write(&project(&owned).join("panel/app.py"), b"new panel\n");
    write(&project(&owned).join("panel/new.py"), b"new file\n");
    assert_message(handoff.commit(), "removed");

    sync(&owned, &staged, &["panel", "docs"], false);
    handoff.commit().unwrap();

    let updated = owned.engine.store().read_state().unwrap();
    assert_eq!(updated.plan_digest, old.plan_digest);
    let core = updated.checkpoint("core.runtime").unwrap();
    assert!(core.ownership.contains_key("/opt/mtproxy-shared443/panel/new.py"));
    assert!(core.ownership.contains_key("/opt/mtproxy-shared443/docs/README.md"));
    assert!(!core.ownership.contains_key("/opt/mtproxy-shared443/panel/static/js/app.js"));
    assert_eq!(
        core.data["ownership"]["/opt/mtproxy-shared443/docs/README.md"],
        serde_json::json!({"preserve": false, "sha256": sha256_hex(b"new docs\n")})
    );
    // The derived journals follow the state (report.json included: Python left it stale).
    assert_eq!(owned.engine.store().read_ownership().unwrap(), updated.ownership(true).unwrap());
    let report = fs::read(owned.engine.store().report_path()).unwrap();
    assert_eq!(report, pc_host::json::pretty2(&updated.report_value()).into_bytes());
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
    assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn panel_handoff_rejects_foreign_file_before_sync() {
    let dir = TempDir::new("foreign");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    write(&project(&owned).join("panel/foreign.py"), b"foreign\n");
    let staged = dir.path().join("staged");
    write(&staged.join("panel/app.py"), b"new panel\n");
    let err = assert_message(make_handoff(&owned, &staged, &["panel"], false).prepare(), "foreign");
    assert_eq!(err.message(), "foreign file in panel sync scope: /opt/mtproxy-shared443/panel/foreign.py");
}

#[test]
fn panel_handoff_rejects_nested_symlink_directory() {
    for legacy in [false, true] {
        for location in ["staged", "installed"] {
            let dir = TempDir::new("nested");
            let root = dir.path().join("root");
            let owned = owned_host(&root, dir.path(), false);
            let staged = dir.path().join("staged");
            super::fakes::copy_tree(&project(&owned).join("panel"), &staged.join("panel"));
            let outside = dir.path().join("outside");
            fs::create_dir(&outside).unwrap();
            let base = if location == "staged" { staged.clone() } else { project(&owned) };
            symlink(&outside, base.join("panel/escape")).unwrap();
            let err = make_handoff(&owned, &staged, &["panel"], legacy).prepare().unwrap_err();
            assert!(err.message().contains("symlink") || err.message().contains("unsafe"), "{}", err.message());
            assert_eq!(err.python_class_name(), "OwnershipError");
        }
    }
}

#[test]
fn panel_handoff_commit_rejects_symlink_directory_inserted_after_preflight() {
    for legacy in [false, true] {
        let dir = TempDir::new("inserted");
        let root = dir.path().join("root");
        let owned = owned_host(&root, dir.path(), false);
        let staged = dir.path().join("staged");
        super::fakes::copy_tree(&project(&owned).join("panel"), &staged.join("panel"));
        let mut handoff = make_handoff(&owned, &staged, &["panel"], legacy);
        handoff.prepare().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, project(&owned).join("panel/escape")).unwrap();
        assert_message(handoff.commit(), "symlink");
    }
}

#[test]
fn panel_handoff_ignores_python_bytecode_without_adopting_it() {
    let dir = TempDir::new("bytecode");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    write(&project(&owned).join("panel/__pycache__/app.cpython-312.pyc"), b"generated cache");
    let staged = dir.path().join("staged");
    write(&staged.join("panel/app.py"), b"new panel\n");
    let mut handoff = make_handoff(&owned, &staged, &["panel"], false);
    handoff.prepare().unwrap();
    assert!(handoff.expected().keys().all(|path| !path.contains("__pycache__")));
}

#[test]
fn panel_handoff_state_is_recoverable_after_crash_before_journal() {
    let dir = TempDir::new("crash");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let staged = dir.path().join("staged");
    write(&staged.join("panel/app.py"), b"new panel\n");
    let mut handoff = make_handoff(&owned, &staged, &["panel"], false);
    handoff.prepare().unwrap();
    sync(&owned, &staged, &["panel"], false);
    owned.engine.store().set_fault_hook(Some(Box::new(|file, _| {
        if file == JournalFile::Ownership {
            return Err(Error::fatal("SimulatedCrash", "simulated crash"));
        }
        Ok(())
    })));
    assert!(handoff.commit().unwrap_err().is_fatal());
    owned.engine.store().set_fault_hook(None);
    assert_eq!(core_digest(&owned, "/opt/mtproxy-shared443/panel/app.py"), sha256_hex(b"new panel\n"));
    assert_eq!(owned.engine.resume().unwrap().status, Status::Active);
    assert_eq!(
        owned.engine.store().read_ownership().unwrap(),
        owned.engine.store().read_state().unwrap().ownership(true).unwrap()
    );
}

#[test]
fn explicit_legacy_recovery_requires_exact_archive_and_restores_repair() {
    let dir = TempDir::new("legacy");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let files: [(&str, &[u8]); 3] = [
        ("VERSION", b"1.1.2-rc.1\n"),
        ("panel/app.py", b"new panel\n"),
        ("release/release.json", b"{\"version\": \"1.1.2-rc.1\"}"),
    ];
    let staged = dir.path().join("candidate");
    for (name, data) in files {
        write(&staged.join(name), data);
    }
    // An update by an old agent replaced the files but left Core's ownership generation as it was.
    fs::remove_dir_all(project(&owned).join("panel")).unwrap();
    for (name, data) in files {
        write(&project(&owned).join(name), data);
    }
    write(&project(&owned).join("panel/__pycache__/app.cpython-312.pyc"), b"generated after update");
    assert_ne!(core_digest(&owned, "/opt/mtproxy-shared443/VERSION"), sha256_hex(files[0].1));
    let names = ["VERSION", "panel", "release"];
    let mut handoff = make_handoff(&owned, &staged, &names, true);
    handoff.prepare().unwrap();
    handoff.commit().unwrap();
    assert_eq!(core_digest(&owned, "/opt/mtproxy-shared443/VERSION"), sha256_hex(files[0].1));
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
    assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn legacy_recovery_refuses_a_tree_that_differs_from_the_archive() {
    let dir = TempDir::new("legacydiff");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let staged = dir.path().join("candidate");
    write(&staged.join("VERSION"), b"9.9.9\n");
    let err = assert_message(make_handoff(&owned, &staged, &["VERSION"], true).prepare(), "differs from archive");
    assert_eq!(err.message(), "installed panel file differs from archive: /opt/mtproxy-shared443/VERSION");
    // A file the archive dropped must be gone from the installed tree too.
    let staged = dir.path().join("candidate-2");
    super::fakes::copy_tree(&project(&owned).join("panel"), &staged.join("panel"));
    fs::remove_file(staged.join("panel/static/js/app.js")).unwrap();
    assert_message(make_handoff(&owned, &staged, &["panel"], true).prepare(), "removed archive file still exists");
}

#[test]
fn panel_handoff_reports_unverified_journal_recovery() {
    let dir = TempDir::new("unverified");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let staged = dir.path().join("staged");
    write(&staged.join("panel/app.py"), b"new panel\n");
    let mut handoff = make_handoff(&owned, &staged, &["panel"], false);
    handoff.prepare().unwrap();
    sync(&owned, &staged, &["panel"], false);
    owned.engine.store().set_fault_hook(Some(Box::new(|file, _| {
        if file == JournalFile::Ownership {
            return Err(std::io::Error::other("journal unavailable").into());
        }
        Ok(())
    })));
    let err = assert_message(handoff.commit(), "could not be restored");
    assert_eq!(err.python_class_name(), "OwnershipRecoveryFailed");
    assert!(matches!(err.as_tx(), Some(TxError::OwnershipRecoveryFailed(_))));
}

#[test]
fn panel_update_refuses_installer_lock_before_tree_mutation() {
    let dir = TempDir::new("lock");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let _held = owned.engine.store().locked().unwrap();
    let err = owned.engine.store().locked().unwrap_err();
    assert_eq!(
        (err.python_class_name(), err.message().as_str()),
        ("TransactionBusyError", "another proxyctl operation is in progress")
    );
}

#[test]
fn panel_update_refuses_unrelated_installer_module_before_mutation() {
    // 3.x checked that the agent imported the project's own `installer/transaction.py`; the
    // compiled-in handoff gates on the journal's schema instead (two-generation rule, §9.4).
    for (state, message) in [("{}", "transaction state is invalid"), ("not json", "transaction state is unreadable")] {
        let dir = TempDir::new("unrelated");
        let root = dir.path().join("root");
        let store_dir = host(&root, "/var/lib/proxy-control/installer");
        write(&store_dir.join("state.json"), state.as_bytes());
        let store = crate::store::TransactionStore::new(&root).unwrap();
        let staged = dir.path().join("staged");
        panel_archive(&staged, b"new agent\n");
        let mut handoff =
            PanelOwnershipHandoff::new(&store, &host(&root, PROJECT), &staged, ARCHIVE_NAMES, false, None).unwrap();
        assert_message(handoff.prepare(), message);
    }
    let dir = TempDir::new("schema");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let mut state = owned.engine.store().read_state().unwrap().to_value();
    state["schema"] = serde_json::json!(2);
    fs::write(owned.engine.store().state_path(), pc_host::json::pretty2(&state)).unwrap();
    let staged = dir.path().join("staged");
    panel_archive(&staged, b"new agent\n");
    assert_message(make_handoff(&owned, &staged, ARCHIVE_NAMES, false).prepare(), "transaction schema is invalid");
}

#[test]
fn panel_update_rebases_active_core_for_repair_and_uninstall() {
    let dir = TempDir::new("rebase");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let old = owned.engine.store().read_state().unwrap();
    let staged = dir.path().join("staged");
    panel_archive(&staged, b"new agent\n");
    let mut handoff = make_handoff(&owned, &staged, ARCHIVE_NAMES, false);
    handoff.prepare().unwrap();
    sync(&owned, &staged, ARCHIVE_NAMES, false);
    handoff.commit().unwrap();
    let updated = owned.engine.store().read_state().unwrap();
    assert_eq!(updated.plan_digest, old.plan_digest);
    assert_eq!(core_digest(&owned, "/opt/mtproxy-shared443/VERSION"), sha256_hex(b"0.11.0\n"));
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
    assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn panel_update_hands_off_installed_agent_package_together_with_core() {
    let dir = TempDir::new("agent");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), true);
    let before = owned.engine.store().read_state().unwrap();
    let staged = dir.path().join("staged");
    panel_archive(&staged, b"new agent\n");
    let mut handoff = make_handoff(&owned, &staged, ARCHIVE_NAMES, false);
    handoff.prepare().unwrap();
    sync(&owned, &staged, ARCHIVE_NAMES, true);
    handoff.commit().unwrap();
    let after = owned.engine.store().read_state().unwrap();
    assert_eq!(after.plan_digest, before.plan_digest);
    let agent = after.checkpoint("version_agent.runtime").unwrap();
    let code = "/opt/proxy-control/version_agent/service.py";
    assert_eq!(agent.ownership[code].sha256, sha256_hex(b"new agent\n"));
    assert_eq!(agent.data["ownership"][code], serde_json::json!(sha256_hex(b"new agent\n")));
    assert!(!agent.ownership.keys().any(|path| path.ends_with("/catalog.py")));
    // Out-of-scope agent files (the unit, the env) keep their entries.
    assert!(agent.ownership.contains_key(UNIT));
    owned.engine.assert_all_owned(&after).unwrap();
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
    assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
}

#[test]
fn panel_update_never_adopts_foreign_agent_code_or_unit() {
    for path in ["/opt/proxy-control/version_agent/service.py", UNIT] {
        let dir = TempDir::new("foreignagent");
        let root = dir.path().join("root");
        let owned = owned_host(&root, dir.path(), true);
        let before = owned.engine.store().read_state().unwrap();
        write(&host(&root, path), b"foreign modification\n");
        let staged = dir.path().join("staged");
        panel_archive(&staged, b"new agent\n");
        assert_message(make_handoff(&owned, &staged, ARCHIVE_NAMES, false).prepare(), "drift");
        assert_eq!(owned.engine.store().read_state().unwrap(), before);
    }
}

#[test]
fn legacy_recovery_reconciles_exact_agent_bytes_only() {
    for drift in [None, Some("code"), Some("unit"), Some("journal")] {
        let dir = TempDir::new("legacyagent");
        let root = dir.path().join("root");
        let owned = owned_host(&root, dir.path(), true);
        let before = owned.engine.store().read_state().unwrap();
        let staged = dir.path().join("candidate");
        write(&staged.join("VERSION"), b"0.11.0\n");
        write(&staged.join("version_agent/service.py"), b"verified new agent\n");
        write(&staged.join("version_agent/new.py"), b"new module\n");
        write(&staged.join("release/release.json"), b"{}");
        let names = ["VERSION", "release"];
        sync(&owned, &staged, &names, true);
        match drift {
            Some("code") => write(&host(&root, "/opt/proxy-control/version_agent/service.py"), b"foreign code\n"),
            Some("unit") => write(&host(&root, UNIT), b"foreign unit\n"),
            _ => {}
        }
        let store = owned.engine.store();
        let mut handoff = make_handoff(&owned, &staged, &names, true);
        match drift {
            Some("journal") => {
                let mut calls = 0;
                store.set_fault_hook(Some(Box::new(move |file, _| {
                    if file == JournalFile::Ownership {
                        calls += 1;
                        if calls == 1 {
                            return Err(std::io::Error::other("journal unavailable").into());
                        }
                    }
                    Ok(())
                })));
                handoff.prepare().unwrap();
                let err = assert_message(handoff.commit(), "journal unavailable");
                assert_eq!(err.python_class_name(), "OSError");
                assert_eq!(store.read_state().unwrap(), before);
                assert_eq!(store.read_ownership().unwrap(), before.ownership(true).unwrap());
            }
            Some(_) => {
                let err = handoff.prepare().unwrap_err();
                assert_eq!(err.python_class_name(), "OwnershipError");
                assert_eq!(store.read_state().unwrap(), before);
            }
            None => {
                handoff.prepare().unwrap();
                handoff.commit().unwrap();
                let updated = store.read_state().unwrap();
                owned.engine.assert_all_owned(&updated).unwrap();
                let agent = updated.checkpoint("version_agent.runtime").unwrap();
                assert_eq!(
                    agent.ownership["/opt/proxy-control/version_agent/new.py"].sha256,
                    sha256_hex(b"new module\n")
                );
                assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
            }
        }
    }
}

#[test]
fn without_an_installer_journal_the_handoff_is_a_no_op() {
    let dir = TempDir::new("nojournal");
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let store = crate::store::TransactionStore::new(&root).unwrap();
    let staged = dir.path().join("staged");
    panel_archive(&staged, b"new agent\n");
    // Any project path: nothing is checked without a journal.
    let mut handoff =
        PanelOwnershipHandoff::new(&store, &dir.path().join("elsewhere"), &staged, ARCHIVE_NAMES, false, None).unwrap();
    handoff.prepare().unwrap();
    handoff.commit().unwrap();
    assert!(!store.state_path().exists());
}

#[test]
fn the_handoff_refuses_a_foreign_project_and_an_unsafe_scope() {
    let dir = TempDir::new("scope");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let staged = dir.path().join("staged");
    panel_archive(&staged, b"new agent\n");
    let mut wrong = PanelOwnershipHandoff::new(
        owned.engine.store(),
        &dir.path().join("elsewhere"),
        &staged,
        &["panel"],
        false,
        None,
    )
    .unwrap();
    assert_message(wrong.prepare(), "panel project path does not match Core ownership");
    assert_message(make_handoff(&owned, &staged, &["secrets"], false).prepare(), "panel sync scope is unsafe");
    assert_message(
        make_handoff(&owned, &staged, &["docs"], false).prepare(),
        "panel archive scope is missing or unsafe",
    );
    // The journal changed between prepare and commit (another writer under the same lock).
    let mut handoff = make_handoff(&owned, &staged, &["panel"], false);
    handoff.prepare().unwrap();
    let mut state = owned.engine.store().read_state().unwrap();
    state.error = Some("TransactionError".into());
    owned.engine.persist(&state).unwrap();
    assert_message(handoff.commit(), "installer transaction changed during panel update");
}
