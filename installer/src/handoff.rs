//! Ownership handoff between the installer and the version-agent (`PanelOwnershipHandoff`,
//! `installer/transaction.py:483-699`, host inventory B.2.7).
//!
//! A panel self-update replaces release-owned trees (the [`PANEL_SYNC`] entries under
//! `/opt/mtproxy-shared443` and `/opt/proxy-control/version_agent`). Those files belong to the
//! installer's Core (and version-agent) checkpoints, so without a handoff the next `repair` or
//! `uninstall` would see drift. The caller holds the operation lock from [`prepare`] through
//! [`commit`] (or its own rollback):
//!
//! 1. [`prepare`] — before anything is synced: the journal is active and consistent, every owned
//!    file is intact, and the trees about to be replaced hold nothing foreign; the staged tree
//!    is hashed (it is the only authority for the new generation).
//! 2. the caller swaps the trees;
//! 3. [`commit`] — the installed trees hold exactly the staged files, then the Core and agent
//!    checkpoints are rebased onto them and the journal is written (`state.json` first; on a
//!    failure the previous journal is restored, or `OwnershipRecoveryFailed`).
//!
//! `legacy` mode (`reconcile-panel-update`) adopts a tree an old agent already synced without a
//! handoff: the installed bytes must equal the verified archive instead.
//!
//! Without an installer journal (a host never installed through the engine) both steps are
//! no-ops.
//!
//! [`prepare`]: PanelOwnershipHandoff::prepare
//! [`commit`]: PanelOwnershipHandoff::commit

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use pc_host::archive::{handoff_allows, AGENT_ROOT, PANEL_AGENT_DIR, PROJECT_DIR};
use pc_host::fs::{owned_path, path_identity, root_path, PathIdentity};
use pc_host::TxError;
use serde_json::{Map, Value};

use crate::engine::{agent_managed_paths, assert_owned, read_matching_plan};
use crate::error::Error;
use crate::journal::{Checkpoint, Ownership, OwnershipEntry, Phase, Status, TransactionState, ORIGIN_INSTALLER};
use crate::store::TransactionStore;

/// The version-agent code directory on the host.
pub const AGENT_CODE_DIR: &str = "/opt/proxy-control/version_agent";
/// The Core checkpoint that owns the project directory.
pub const CORE_ACTION: &str = "core.runtime";
/// The version-agent checkpoint.
pub const AGENT_ACTION: &str = "version_agent.runtime";

pub(crate) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// `Path(host).is_relative_to(base)` on journal keys (component-wise).
pub(crate) fn within(host: &str, base: &str) -> bool {
    Path::new(host).starts_with(base)
}

/// One path found under a tree (`Path.rglob('*')`), with its parts relative to the tree.
pub(crate) struct Found {
    pub path: PathBuf,
    pub parts: Vec<String>,
}

impl Found {
    pub fn relative(&self) -> String {
        self.parts.join("/")
    }

    /// Python bytecode the 3.x agent generated in an installed tree (`__pycache__/…`, `*.pyc`).
    pub fn is_bytecode(&self) -> bool {
        (self.parts.iter().any(|part| part == "__pycache__") || self.path.extension().is_some_and(|ext| ext == "pyc"))
            && fs::symlink_metadata(&self.path).map(|m| m.file_type().is_file()).unwrap_or(false)
    }
}

/// Every path under `directory` (not following symlinks), sorted, each before its children.
pub(crate) fn rglob(directory: &Path) -> Result<Vec<Found>, TxError> {
    let mut found = Vec::new();
    walk(directory, &mut Vec::new(), &mut found)?;
    Ok(found)
}

fn walk(directory: &Path, parts: &mut Vec<String>, found: &mut Vec<Found>) -> Result<(), TxError> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        parts.push(name);
        found.push(Found { path: path.clone(), parts: parts.clone() });
        if entry.file_type()?.is_dir() {
            walk(&path, parts, found)?;
        }
        parts.pop();
    }
    Ok(())
}

/// The paths a tree target covers: every descendant of a directory, the target itself for a
/// file, nothing when it is missing. A symlink anywhere (the target included) refuses with
/// `symlink_message`.
pub(crate) fn scope_paths(target: &Path, symlink_message: &str) -> Result<Vec<Found>, TxError> {
    if is_symlink(target) {
        return Err(crate::error::ownership(symlink_message));
    }
    if !target.exists() {
        return Ok(Vec::new());
    }
    let found =
        if target.is_dir() { rglob(target)? } else { vec![Found { path: target.to_path_buf(), parts: Vec::new() }] };
    let mut files = Vec::new();
    for item in found {
        if is_symlink(&item.path) {
            return Err(crate::error::ownership(symlink_message));
        }
        if !item.path.is_dir() {
            files.push(item);
        }
    }
    Ok(files)
}

/// `host_base` plus the relative parts (`/…` only when there are parts).
pub(crate) fn host_key(host_base: &str, found: &Found) -> String {
    if found.parts.is_empty() {
        host_base.to_string()
    } else {
        format!("{host_base}/{}", found.relative())
    }
}

/// Hashes a staged tree entry: regular files only, no symlinks; `{host: identity}` with
/// `host_prefix + <path relative to the staging root>`.
pub(crate) fn stage_entry(
    staged: &Path,
    name: &str,
    host_prefix: &str,
    result: &mut BTreeMap<String, PathIdentity>,
) -> Result<(), TxError> {
    let source = staged.join(name);
    if !source.exists() || is_symlink(&source) {
        return Err(crate::error::ownership("panel archive scope is missing or unsafe"));
    }
    let found = if source.is_dir() { rglob(&source)? } else { vec![Found { path: source.clone(), parts: Vec::new() }] };
    for item in found {
        if is_symlink(&item.path) {
            return Err(crate::error::ownership("panel archive contains an unsafe symlink"));
        }
        if item.path.is_dir() {
            continue;
        }
        if !item.path.is_file() || item.parts.iter().any(|part| part.contains('\u{fffd}')) {
            return Err(crate::error::ownership("panel archive contains an unsafe path"));
        }
        let relative = if item.parts.is_empty() { name.to_string() } else { format!("{name}/{}", item.relative()) };
        result.insert(format!("{host_prefix}{relative}"), path_identity(&item.path)?);
    }
    Ok(())
}

/// The checkpoint's ownership must agree with its own declaration (`data.ownership`).
pub(crate) fn check_declaration(checkpoint: &Checkpoint) -> Result<(), TxError> {
    let declaration = checkpoint
        .data
        .get("ownership")
        .and_then(Value::as_object)
        .ok_or_else(|| crate::error::ownership("checkpoint ownership declaration is invalid"))?;
    for (host, entry) in &checkpoint.ownership {
        let digest = match declaration.get(host) {
            Some(Value::Object(declared)) => declared.get("sha256"),
            other => other,
        };
        if digest.and_then(Value::as_str) != Some(entry.sha256.as_str()) {
            return Err(crate::error::ownership("checkpoint ownership disagrees with adapter data"));
        }
    }
    Ok(())
}

/// The journal checks both handoffs start with: an active installer transaction whose plan and
/// derived ownership journal agree with `state.json`.
pub(crate) fn read_active_state(store: &TransactionStore, inactive_message: &str) -> Result<TransactionState, TxError> {
    let state = store.read_state()?;
    read_matching_plan(store, &state)?;
    if state.status != Status::Active || state.origin != ORIGIN_INSTALLER {
        return Err(crate::error::transaction(inactive_message));
    }
    if store.read_ownership()? != state.ownership(true)? {
        return Err(crate::error::ownership("ownership journal disagrees with checkpoint"));
    }
    Ok(state)
}

/// Writes a rebased journal (`state.json`, then `ownership.json`, then `report.json`); on an
/// ordinary failure restores the previous one and returns the failure, or `recovery_message`
/// as `OwnershipRecoveryFailed` when even the restore fails. A fatal error (the process dying)
/// leaves the new state with stale derived files, which `resume` rebuilds.
pub(crate) fn write_rebased(
    store: &TransactionStore,
    previous: &TransactionState,
    updated: &TransactionState,
    recovery_message: &str,
) -> Result<(), Error> {
    let write = |state: &TransactionState| -> Result<(), Error> {
        store.write_state(state)?;
        store.write_ownership(&state.ownership(true)?)?;
        store.write_report(&state.report_value())
    };
    match write(updated) {
        Ok(()) => Ok(()),
        Err(err) if err.is_fatal() => Err(err),
        Err(err) => match write(previous) {
            Ok(()) => Err(err),
            Err(restore) if restore.is_fatal() => Err(restore),
            Err(_) => Err(TxError::OwnershipRecoveryFailed(recovery_message.into()).into()),
        },
    }
}

/// Rebases the Core (and agent) checkpoints onto the staged identities (`commit`, the part
/// after the checks): in-scope paths are dropped, every staged path under the checkpoint's base
/// is owned as `{kind, preserve: false, mutable: false, sha256}`, and `data.ownership` declares
/// `{preserve: false, sha256}` (Core) or the bare digest (agent).
pub fn rebase_panel_ownership(
    state: &TransactionState,
    names: &[String],
    expected: &BTreeMap<String, PathIdentity>,
    include_agent: bool,
) -> Result<TransactionState, TxError> {
    let in_scope = |host: &str| panel_in_scope(host, names, include_agent);
    let mut updated = state.clone();
    let mut targets = vec![(CORE_ACTION, PROJECT_DIR)];
    if include_agent {
        targets.push((AGENT_ACTION, AGENT_CODE_DIR));
    }
    for (action_id, base) in targets {
        let is_agent = action_id == AGENT_ACTION;
        let checkpoint = state
            .checkpoint(action_id)
            .ok_or_else(|| {
                crate::error::transaction(if is_agent {
                    "active version-agent checkpoint is unavailable"
                } else {
                    "active Core checkpoint is unavailable"
                })
            })?
            .clone();
        let mut ownership: Ownership = checkpoint
            .ownership
            .iter()
            .filter(|(path, _)| !in_scope(path))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut declaration: Map<String, Value> = checkpoint
            .data
            .get("ownership")
            .and_then(Value::as_object)
            .ok_or_else(|| crate::error::ownership("checkpoint ownership declaration is invalid"))?
            .iter()
            .filter(|(path, _)| !in_scope(path))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (host, identity) in expected {
            if !within(host, base) {
                continue;
            }
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
            let declared = if is_agent {
                Value::String(identity.sha256.clone())
            } else {
                let mut entry = Map::new();
                entry.insert("preserve".into(), Value::Bool(false));
                entry.insert("sha256".into(), Value::String(identity.sha256.clone()));
                Value::Object(entry)
            };
            declaration.insert(host.clone(), declared);
        }
        let mut data = checkpoint.data.clone();
        data.insert("ownership".into(), Value::Object(declaration));
        updated.with_checkpoint(Checkpoint { data, ownership, ..checkpoint });
    }
    Ok(updated)
}

/// `_in_scope`: the agent code (when it is handed off) and the synced entries of the project.
fn panel_in_scope(host: &str, names: &[String], include_agent: bool) -> bool {
    if include_agent && within(host, AGENT_CODE_DIR) {
        return true;
    }
    match Path::new(host).strip_prefix(PROJECT_DIR) {
        Ok(relative) => match relative.components().next() {
            Some(Component::Normal(first)) => names.iter().any(|name| first == name.as_str()),
            _ => false,
        },
        Err(_) => false,
    }
}

/// The handoff of one panel update.
pub struct PanelOwnershipHandoff<'s> {
    store: &'s TransactionStore,
    project: PathBuf,
    staged: PathBuf,
    names: Vec<String>,
    legacy: bool,
    agent_dir: PathBuf,
    state: Option<TransactionState>,
    core: Option<Checkpoint>,
    agent: Option<Checkpoint>,
    expected: BTreeMap<String, PathIdentity>,
}

impl<'s> PanelOwnershipHandoff<'s> {
    /// `PanelOwnershipHandoff(store, project, staged, names, legacy=…, agent_dir=…)`: `names` are
    /// the synced entries present in the staged tree (without `version_agent`); `agent_dir`
    /// defaults to `<root>/opt/proxy-control`.
    pub fn new(
        store: &'s TransactionStore,
        project: &Path,
        staged: &Path,
        names: &[&str],
        legacy: bool,
        agent_dir: Option<&Path>,
    ) -> Result<PanelOwnershipHandoff<'s>, TxError> {
        let agent_dir = match agent_dir {
            Some(path) => path.to_path_buf(),
            None => root_path(store.root(), AGENT_ROOT)?,
        };
        Ok(PanelOwnershipHandoff {
            store,
            project: project.to_path_buf(),
            staged: staged.to_path_buf(),
            names: names.iter().map(|name| name.to_string()).collect(),
            legacy,
            agent_dir,
            state: None,
            core: None,
            agent: None,
            expected: BTreeMap::new(),
        })
    }

    /// The staged identities `prepare` recorded (`host path → identity`).
    pub fn expected(&self) -> &BTreeMap<String, PathIdentity> {
        &self.expected
    }

    fn in_scope(&self, host: &str) -> bool {
        panel_in_scope(host, &self.names, self.agent.is_some())
    }

    /// `(installed target, host base, owning checkpoint)` for each replaced tree.
    fn targets(&self) -> Vec<(PathBuf, String, &Checkpoint)> {
        let mut targets = Vec::new();
        if let Some(core) = &self.core {
            for name in &self.names {
                targets.push((self.project.join(name), format!("{PROJECT_DIR}/{name}"), core));
            }
        }
        if let Some(agent) = &self.agent {
            targets.push((self.agent_dir.join(PANEL_AGENT_DIR), AGENT_CODE_DIR.to_string(), agent));
        }
        targets
    }

    fn stage_files(&self) -> Result<BTreeMap<String, PathIdentity>, TxError> {
        if self.names.iter().any(|name| !handoff_allows(name)) {
            return Err(crate::error::ownership("panel sync scope is unsafe"));
        }
        let mut result = BTreeMap::new();
        for name in &self.names {
            stage_entry(&self.staged, name, &format!("{PROJECT_DIR}/"), &mut result)?;
        }
        if self.agent.is_some() {
            stage_entry(&self.staged, PANEL_AGENT_DIR, &format!("{AGENT_ROOT}/"), &mut result)?;
        }
        Ok(result)
    }

    /// Checks the journal, the owned files and the trees about to be replaced, and hashes the
    /// staged tree. Without an installer journal it does nothing.
    pub fn prepare(&mut self) -> Result<(), Error> {
        if !self.store.state_exists() {
            return Ok(());
        }
        let root = self.store.root();
        if self.project != root_path(root, PROJECT_DIR)? {
            return Err(crate::error::ownership("panel project path does not match Core ownership").into());
        }
        let state = read_active_state(self.store, "panel ownership requires an active installer transaction")?;
        let core: Vec<&Checkpoint> =
            state.checkpoints.iter().filter(|item| item.adapter == "core" && item.phase == Phase::Verified).collect();
        if core.len() != 1 || core[0].action_id != CORE_ACTION {
            return Err(crate::error::transaction("active Core checkpoint is unavailable").into());
        }
        self.core = Some(core[0].clone());
        let agents: Vec<&Checkpoint> =
            state.checkpoints.iter().filter(|item| item.adapter == "version_agent").collect();
        if !agents.is_empty() && self.staged.join(PANEL_AGENT_DIR).exists() {
            if agents.len() != 1 || agents[0].phase != Phase::Verified || agents[0].action_id != AGENT_ACTION {
                return Err(crate::error::transaction("active version-agent checkpoint is unavailable").into());
            }
            if self.agent_dir != root_path(root, AGENT_ROOT)? {
                return Err(crate::error::ownership("version-agent path does not match installer ownership").into());
            }
            self.agent = Some(agents[0].clone());
        }
        for checkpoint in self.core.iter().chain(self.agent.iter()) {
            check_declaration(checkpoint)?;
        }
        let stage = self.stage_files()?;
        let owned = state.ownership(true)?;
        let agent_managed = agent_managed_paths();
        if self.legacy {
            let outside: Ownership =
                owned.iter().filter(|(path, _)| !self.in_scope(path)).map(|(k, v)| (k.clone(), v.clone())).collect();
            assert_owned(root, &outside, &agent_managed)?;
        } else {
            assert_owned(root, &owned, &agent_managed)?;
        }
        // Each replaced tree may hold only files its checkpoint owns.
        for (target, host_base, checkpoint) in self.targets() {
            for found in scope_paths(&target, "panel sync scope contains an unsafe symlink")? {
                // Python writes bytecode into installed source trees at runtime; it is never
                // owned and the replacement discards it.
                if found.is_bytecode() {
                    continue;
                }
                let host = host_key(&host_base, &found);
                let adopted = self.legacy
                    && stage
                        .get(&host)
                        .is_some_and(|identity| path_identity(&found.path).ok().as_ref() == Some(identity));
                if !checkpoint.ownership.contains_key(&host) && !adopted {
                    return Err(crate::error::ownership(format!("foreign file in panel sync scope: {host}")).into());
                }
            }
        }
        if self.legacy {
            for (host, identity) in &stage {
                if &path_identity(&owned_path(root, host)?.1)? != identity {
                    return Err(
                        crate::error::ownership(format!("installed panel file differs from archive: {host}")).into()
                    );
                }
            }
            for host in owned.keys() {
                if self.in_scope(host) && !stage.contains_key(host) {
                    let path = owned_path(root, host)?.1;
                    if path.exists() || is_symlink(&path) {
                        return Err(
                            crate::error::ownership(format!("removed archive file still exists: {host}")).into()
                        );
                    }
                }
            }
        }
        self.state = Some(state);
        self.expected = stage;
        Ok(())
    }

    /// Checks the swapped trees against the staged identities and rebases the journal onto them.
    pub fn commit(&mut self) -> Result<(), Error> {
        let Some(previous) = self.state.clone() else {
            return Ok(());
        };
        if self.core.is_none() {
            return Err(crate::error::transaction("panel handoff was not prepared").into());
        }
        let root = self.store.root();
        if self.store.read_state()? != previous {
            return Err(crate::error::transaction("installer transaction changed during panel update").into());
        }
        let outside: Ownership =
            previous.ownership(true)?.into_iter().filter(|(path, _)| !self.in_scope(path)).collect();
        assert_owned(root, &outside, &agent_managed_paths())?;
        for (target, host_base, _) in self.targets() {
            for found in scope_paths(&target, "panel sync scope contains an unsafe symlink")? {
                // Bytecode may be regenerated after an old-agent update; it is neither archive
                // evidence nor newly owned state.
                if self.legacy && found.is_bytecode() {
                    continue;
                }
                let host = host_key(&host_base, &found);
                if !self.expected.contains_key(&host) {
                    return Err(
                        crate::error::ownership(format!("removed or foreign panel file remains: {host}")).into()
                    );
                }
            }
        }
        for (host, identity) in &self.expected {
            if &path_identity(&owned_path(root, host)?.1)? != identity {
                return Err(crate::error::ownership(format!("panel file differs from verified archive: {host}")).into());
            }
        }
        let updated = rebase_panel_ownership(&previous, &self.names, &self.expected, self.agent.is_some())?;
        // State is authoritative: a crash after its write leaves stale derived files that
        // `resume` rebuilds; the inverse order would strand both.
        write_rebased(
            self.store,
            &previous,
            &updated,
            "panel ownership handoff failed and previous journal could not be restored",
        )
    }
}
