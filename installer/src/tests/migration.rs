//! `AgentMigration`: the 3.x Python agent replaced by the Rust binary under an installer journal.

use std::fs;
use std::path::{Path, PathBuf};

use pc_host::fs::sha256_hex;
use pc_host::TxError;
use serde_json::json;

use super::fakes::{host, owned_host, replace_tree, write, OwnedHost, AGENT_CODE, ENV, TMPFILES, UNIT};
use crate::error::Error;
use crate::journal::Status;
use crate::migration::AgentMigration;
use crate::store::{JournalFile, TransactionStore};
use crate::testkit::TempDir;

const BINARY: &str = "bin/linux-amd64/proxy-control-version-agent";
const RUST_UNIT: &[u8] =
    b"[Service]\nExecStart=/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent\n";

/// A 4.0 release tree: the agent crate and its binary.
fn release(work: &Path) -> PathBuf {
    let staged = work.join("release");
    write(&staged.join("version_agent").join(BINARY), b"\x7fELF rust agent");
    write(&staged.join("version_agent/Cargo.toml"), b"[package]\nname = \"version_agent\"\n");
    write(&staged.join("version_agent/src/main.rs"), b"fn main() {}\n");
    staged
}

/// What `migrate-agent` does to the files between prepare and commit.
fn swap(owned: &OwnedHost, staged: &Path) {
    replace_tree(&staged.join("version_agent"), &host(&owned.root, AGENT_CODE));
    write(&host(&owned.root, UNIT), RUST_UNIT);
}

fn assert_message<T: std::fmt::Debug>(result: Result<T, Error>, fragment: &str) -> Error {
    let err = result.expect_err("the migration must refuse");
    assert!(err.message().contains(fragment), "{:?} does not mention {fragment:?}", err.message());
    err
}

#[test]
fn a_host_without_a_journal_needs_no_rebase() {
    let dir = TempDir::new("nojournal");
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let store = TransactionStore::new(&root).unwrap();
    let staged = release(dir.path());
    let mut migration = AgentMigration::new(&store, &staged);
    assert!(!migration.prepare().unwrap());
    assert_eq!(migration.commit().unwrap(), None);
    assert!(!store.state_path().exists());
}

#[test]
fn a_journal_without_an_agent_checkpoint_needs_no_rebase() {
    let dir = TempDir::new("noagent");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), false);
    let before = owned.engine.store().read_state().unwrap();
    let staged = release(dir.path());
    let mut migration = AgentMigration::new(owned.engine.store(), &staged);
    assert!(!migration.prepare().unwrap());
    assert_eq!(migration.commit().unwrap(), None);
    assert_eq!(owned.engine.store().read_state().unwrap(), before);
}

#[test]
fn the_rust_agent_tree_and_unit_replace_the_python_ones_in_the_journal() {
    let dir = TempDir::new("migrate");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), true);
    let before = owned.engine.store().read_state().unwrap();
    // 3.x bytecode next to the Python sources never blocks the migration.
    write(&host(&root, AGENT_CODE).join("__pycache__/service.cpython-312.pyc"), b"cache");
    let staged = release(dir.path());
    let mut migration = AgentMigration::new(owned.engine.store(), &staged);
    assert!(migration.prepare().unwrap());
    swap(&owned, &staged);

    let updated = migration.commit().unwrap().unwrap();

    let store = owned.engine.store();
    assert_eq!(store.read_state().unwrap(), updated);
    assert_eq!(updated.plan_digest, before.plan_digest);
    assert_eq!(store.read_ownership().unwrap(), updated.ownership(true).unwrap());
    let agent = updated.checkpoint("version_agent.runtime").unwrap();
    let binary = format!("{AGENT_CODE}/{BINARY}");
    assert_eq!(agent.ownership[&binary].sha256, sha256_hex(b"\x7fELF rust agent"));
    assert_eq!((agent.ownership[&binary].mutable, agent.ownership[&binary].preserve), (Some(false), false));
    assert_eq!(agent.data["ownership"][&binary], json!(sha256_hex(b"\x7fELF rust agent")));
    assert!(!agent.ownership.keys().any(|path| path.ends_with(".py")));
    assert_eq!(agent.ownership[UNIT].sha256, sha256_hex(RUST_UNIT));
    assert_eq!(agent.data["ownership"][UNIT], json!(sha256_hex(RUST_UNIT)));
    // The env keeps its mutable declaration; the tmpfiles file and Core are untouched.
    let previous = before.checkpoint("version_agent.runtime").unwrap();
    assert_eq!(agent.ownership[ENV], previous.ownership[ENV]);
    assert_eq!(agent.data["ownership"][ENV]["mutable"], json!(true));
    assert_eq!(agent.ownership[TMPFILES], previous.ownership[TMPFILES]);
    assert_eq!(updated.checkpoint("core.runtime"), before.checkpoint("core.runtime"));
    // The installation stays repairable and removable.
    owned.engine.assert_all_owned(&updated).unwrap();
    assert_eq!(owned.engine.repair().unwrap().status, Status::Active);
    assert_eq!(owned.engine.uninstall(false).unwrap().status, Status::Uninstalled);
    assert!(!host(&root, AGENT_CODE).join(BINARY).exists());
}

#[test]
fn prepare_refuses_foreign_agent_code_and_a_drifted_unit() {
    for (path, message) in [
        (
            format!("{AGENT_CODE}/extra.py"),
            "foreign file in version-agent scope: /opt/proxy-control/version_agent/extra.py",
        ),
        (UNIT.to_string(), "owned file drifted: /etc/systemd/system/version-agent.service"),
        (format!("{AGENT_CODE}/service.py"), "owned file drifted: /opt/proxy-control/version_agent/service.py"),
    ] {
        let dir = TempDir::new("foreign");
        let root = dir.path().join("root");
        let owned = owned_host(&root, dir.path(), true);
        let before = owned.engine.store().read_state().unwrap();
        write(&host(&root, &path), b"foreign\n");
        let staged = release(dir.path());
        let err = assert_message(AgentMigration::new(owned.engine.store(), &staged).prepare(), message);
        assert_eq!(err.python_class_name(), "OwnershipError");
        assert_eq!(owned.engine.store().read_state().unwrap(), before);
    }
}

#[test]
fn commit_refuses_leftovers_and_bytes_other_than_the_release() {
    let dir = TempDir::new("leftover");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), true);
    let staged = release(dir.path());
    let mut migration = AgentMigration::new(owned.engine.store(), &staged);
    migration.prepare().unwrap();
    swap(&owned, &staged);
    write(&host(&root, AGENT_CODE).join("service.py"), b"old agent\n");
    assert_message(
        migration.commit(),
        "removed or foreign version-agent file remains: /opt/proxy-control/version_agent/service.py",
    );
    fs::remove_file(host(&root, AGENT_CODE).join("service.py")).unwrap();
    write(&host(&root, AGENT_CODE).join("src/main.rs"), b"tampered\n");
    assert_message(migration.commit(), "version-agent file differs from verified release");
    write(&host(&root, AGENT_CODE).join("src/main.rs"), b"fn main() {}\n");
    // Core's files outside the scope must still be intact.
    write(&host(&root, "/opt/mtproxy-shared443/VERSION"), b"foreign\n");
    assert_message(migration.commit(), "owned file drifted: /opt/mtproxy-shared443/VERSION");
}

#[test]
fn a_failed_journal_write_restores_the_previous_journal() {
    let dir = TempDir::new("restore");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), true);
    let before = owned.engine.store().read_state().unwrap();
    let staged = release(dir.path());
    let store = owned.engine.store();
    let mut migration = AgentMigration::new(store, &staged);
    migration.prepare().unwrap();
    swap(&owned, &staged);
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
    assert_message(migration.commit(), "journal unavailable");
    assert_eq!(store.read_state().unwrap(), before);
    assert_eq!(store.read_ownership().unwrap(), before.ownership(true).unwrap());

    store.set_fault_hook(Some(Box::new(|file, _| {
        if file == JournalFile::Ownership {
            return Err(std::io::Error::other("journal unavailable").into());
        }
        Ok(())
    })));
    let err = assert_message(migration.commit(), "could not be restored");
    assert!(matches!(err.as_tx(), Some(TxError::OwnershipRecoveryFailed(_))));
}

#[test]
fn a_changed_or_interrupted_journal_is_refused() {
    let dir = TempDir::new("changed");
    let root = dir.path().join("root");
    let owned = owned_host(&root, dir.path(), true);
    let staged = release(dir.path());
    let mut migration = AgentMigration::new(owned.engine.store(), &staged);
    migration.prepare().unwrap();
    let mut state = owned.engine.store().read_state().unwrap();
    state.error = Some("TransactionError".into());
    owned.engine.persist(&state).unwrap();
    assert_message(migration.commit(), "installer transaction changed during version-agent migration");
    state.status = Status::Applying;
    owned.engine.persist(&state).unwrap();
    assert_message(
        AgentMigration::new(owned.engine.store(), &staged).prepare(),
        "version-agent migration requires an active installer transaction",
    );
}
