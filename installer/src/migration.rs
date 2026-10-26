//! The version-agent migration's journal rebase (host inventory §9.4, new in 4.0).
//!
//! `update-host` replaces the 3.x Python agent with the Rust binary before anything else: it
//! stops the agent, installs `version_agent/` from the verified release tree (binary included)
//! and writes a unit whose `ExecStart` is the binary. On a host installed through the engine
//! those files belong to the `version_agent.runtime` checkpoint, so the journal is rebased onto
//! the new bytes, shaped like [`PanelOwnershipHandoff`](crate::handoff::PanelOwnershipHandoff):
//!
//! 1. [`AgentMigration::prepare`] (under the operation lock, before any file changes): the
//!    journal is active and consistent, every owned file is intact, the installed agent tree
//!    holds only files the agent checkpoint owns (3.x bytecode excepted), and the release's
//!    `version_agent/` tree is hashed.
//! 2. the caller swaps the tree and writes the unit;
//! 3. [`AgentMigration::commit`]: the installed tree holds exactly the release files; every
//!    path outside the scope is still intact; the checkpoint is rebased: the old code entries
//!    go, each release file is owned (`preserve: false, mutable: false`, declared by its bare
//!    digest as the agent adapter declares code), and the re-hashed single files (the unit and
//!    the env by default) keep their flags and declaration shape with the new digest. The
//!    journal is written state-first, the previous one restored on a failure.
//!
//! Hosts without a journal, or with a journal that has no version-agent checkpoint (the agent
//! was never installer-owned), need no rebase: both steps report `false`/`None`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pc_host::archive::{AGENT_ROOT, PANEL_AGENT_DIR};
use pc_host::fs::{owned_path, path_identity, root_path, PathIdentity};
use pc_host::TxError;
use serde_json::{Map, Value};

use crate::engine::{agent_managed_paths, assert_owned};
use crate::error::Error;
use crate::handoff::{
    check_declaration, host_key, read_active_state, scope_paths, stage_entry, within, write_rebased, AGENT_ACTION,
    AGENT_CODE_DIR,
};
use crate::journal::{Checkpoint, Ownership, OwnershipEntry, Phase, TransactionState};
use crate::store::TransactionStore;

/// The agent's systemd unit (its `ExecStart` changes in the migration).
pub const AGENT_UNIT: &str = "/etc/systemd/system/version-agent.service";
/// The agent's environment file (mutable: the agent and the operator edit it).
pub const AGENT_ENV: &str = "/etc/proxy-control/version-agent.env";
/// The single files a migration re-hashes by default.
pub const MIGRATION_REHASHED: &[&str] = &[AGENT_UNIT, AGENT_ENV];

const SYMLINK_MESSAGE: &str = "version-agent scope contains an unsafe symlink";

/// Rebases the agent checkpoint (the pure part of [`AgentMigration::commit`]): entries under the
/// agent code directory and the paths in `rehashed` go; `expected` (release files) and
/// `rehashed` (single files with their new identity) come in.
pub fn rebase_agent_ownership(
    state: &TransactionState,
    expected: &BTreeMap<String, PathIdentity>,
    rehashed: &BTreeMap<String, PathIdentity>,
) -> Result<TransactionState, TxError> {
    let checkpoint = state
        .checkpoint(AGENT_ACTION)
        .ok_or_else(|| crate::error::transaction("active version-agent checkpoint is unavailable"))?
        .clone();
    let in_scope = |host: &str| within(host, AGENT_CODE_DIR) || rehashed.contains_key(host);
    let previous_declaration = checkpoint
        .data
        .get("ownership")
        .and_then(Value::as_object)
        .ok_or_else(|| crate::error::ownership("checkpoint ownership declaration is invalid"))?;
    let mut ownership: Ownership =
        checkpoint.ownership.iter().filter(|(path, _)| !in_scope(path)).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut declaration: Map<String, Value> =
        previous_declaration.iter().filter(|(path, _)| !in_scope(path)).map(|(k, v)| (k.clone(), v.clone())).collect();
    for (host, identity) in expected {
        ownership.insert(
            host.clone(),
            OwnershipEntry {
                action_id: checkpoint.action_id.clone(),
                adapter: checkpoint.adapter.clone(),
                kind: identity.kind.as_str().into(),
                mutable: Some(false),
                preserve: false,
                sha256: identity.sha256.clone(),
            },
        );
        declaration.insert(host.clone(), Value::String(identity.sha256.clone()));
    }
    for (host, identity) in rehashed {
        let previous = checkpoint
            .ownership
            .get(host)
            .ok_or_else(|| crate::error::ownership(format!("version-agent checkpoint does not own {host}")))?;
        ownership.insert(
            host.clone(),
            OwnershipEntry { kind: identity.kind.as_str().into(), sha256: identity.sha256.clone(), ..previous.clone() },
        );
        let declared = match previous_declaration.get(host) {
            Some(Value::Object(flags)) => {
                let mut flags = flags.clone();
                flags.insert("sha256".into(), Value::String(identity.sha256.clone()));
                Value::Object(flags)
            }
            _ => Value::String(identity.sha256.clone()),
        };
        declaration.insert(host.clone(), declared);
    }
    let mut data = checkpoint.data.clone();
    data.insert("ownership".into(), Value::Object(declaration));
    let mut updated = state.clone();
    updated.with_checkpoint(Checkpoint { data, ownership, ..checkpoint });
    Ok(updated)
}

/// The journal side of one agent migration.
pub struct AgentMigration<'s> {
    store: &'s TransactionStore,
    staged: PathBuf,
    rehashed: BTreeSet<String>,
    state: Option<TransactionState>,
    agent: Option<Checkpoint>,
    expected: BTreeMap<String, PathIdentity>,
}

impl<'s> AgentMigration<'s> {
    /// `staged` is the verified release tree (it holds `version_agent/`).
    pub fn new(store: &'s TransactionStore, staged: &Path) -> AgentMigration<'s> {
        AgentMigration {
            store,
            staged: staged.to_path_buf(),
            rehashed: MIGRATION_REHASHED.iter().map(|path| path.to_string()).collect(),
            state: None,
            agent: None,
            expected: BTreeMap::new(),
        }
    }

    /// Replaces the single files re-hashed at commit (host paths the agent checkpoint owns).
    pub fn with_rehashed(mut self, paths: &[&str]) -> AgentMigration<'s> {
        self.rehashed = paths.iter().map(|path| path.to_string()).collect();
        self
    }

    /// The release identities `prepare` recorded.
    pub fn expected(&self) -> &BTreeMap<String, PathIdentity> {
        &self.expected
    }

    fn installed_tree(&self) -> Result<PathBuf, TxError> {
        root_path(self.store.root(), AGENT_CODE_DIR)
    }

    /// The re-hashed files this journal's agent checkpoint actually owns.
    fn owned_rehashed(&self, agent: &Checkpoint) -> BTreeSet<String> {
        self.rehashed.iter().filter(|path| agent.ownership.contains_key(*path)).cloned().collect()
    }

    /// Checks the journal and the installed agent before any file changes. `Ok(false)`: nothing
    /// to rebase (no journal, or the agent is not installer-owned).
    pub fn prepare(&mut self) -> Result<bool, Error> {
        if !self.store.state_exists() {
            return Ok(false);
        }
        let root = self.store.root();
        let state = read_active_state(self.store, "version-agent migration requires an active installer transaction")?;
        let agents: Vec<&Checkpoint> =
            state.checkpoints.iter().filter(|item| item.adapter == "version_agent").collect();
        if agents.is_empty() {
            return Ok(false);
        }
        if agents.len() != 1 || agents[0].phase != Phase::Verified || agents[0].action_id != AGENT_ACTION {
            return Err(crate::error::transaction("active version-agent checkpoint is unavailable").into());
        }
        let agent = agents[0].clone();
        check_declaration(&agent)?;
        let mut expected = BTreeMap::new();
        stage_entry(&self.staged, PANEL_AGENT_DIR, &format!("{AGENT_ROOT}/"), &mut expected)?;
        assert_owned(root, &state.ownership(true)?, &agent_managed_paths())?;
        for found in scope_paths(&self.installed_tree()?, SYMLINK_MESSAGE)? {
            if found.is_bytecode() {
                continue;
            }
            let host = host_key(AGENT_CODE_DIR, &found);
            if !agent.ownership.contains_key(&host) {
                return Err(crate::error::ownership(format!("foreign file in version-agent scope: {host}")).into());
            }
        }
        self.state = Some(state);
        self.agent = Some(agent);
        self.expected = expected;
        Ok(true)
    }

    /// Checks the swapped tree and rebases the journal onto it. `Ok(None)` when `prepare` found
    /// nothing to rebase.
    pub fn commit(&mut self) -> Result<Option<TransactionState>, Error> {
        let (Some(previous), Some(agent)) = (self.state.clone(), self.agent.clone()) else {
            return Ok(None);
        };
        let root = self.store.root();
        if self.store.read_state()? != previous {
            return Err(
                crate::error::transaction("installer transaction changed during version-agent migration").into()
            );
        }
        let rehashed_paths = self.owned_rehashed(&agent);
        let in_scope = |host: &str| within(host, AGENT_CODE_DIR) || rehashed_paths.contains(host);
        let outside: Ownership = previous.ownership(true)?.into_iter().filter(|(path, _)| !in_scope(path)).collect();
        assert_owned(root, &outside, &agent_managed_paths())?;
        for found in scope_paths(&self.installed_tree()?, SYMLINK_MESSAGE)? {
            let host = host_key(AGENT_CODE_DIR, &found);
            if !self.expected.contains_key(&host) {
                return Err(
                    crate::error::ownership(format!("removed or foreign version-agent file remains: {host}")).into()
                );
            }
        }
        for (host, identity) in &self.expected {
            if &path_identity(&owned_path(root, host)?.1)? != identity {
                return Err(crate::error::ownership(format!(
                    "version-agent file differs from verified release: {host}"
                ))
                .into());
            }
        }
        let mut rehashed = BTreeMap::new();
        for host in &rehashed_paths {
            rehashed.insert(host.clone(), path_identity(&owned_path(root, host)?.1)?);
        }
        let updated = rebase_agent_ownership(&previous, &self.expected, &rehashed)?;
        write_rebased(
            self.store,
            &previous,
            &updated,
            "version-agent ownership migration failed and previous journal could not be restored",
        )?;
        Ok(Some(updated))
    }
}
