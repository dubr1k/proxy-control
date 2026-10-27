//! The panel's self-update (`_update_panel_async`, `_panel_worker`, `_update_panel`,
//! `_sync_and_restart_panel*`, `_restore_panel`): the release tree into the project directory and
//! the agent's own tree into `/opt/proxy-control/version_agent`, under the host operation lock and
//! the installer's ownership handoff; a rebuild of the panel image, a database snapshot, a verified
//! restart; on any failure the files, the database and the image come back. When the agent's own
//! tree changed (the binary included), systemd restarts the agent once the verdict is recorded.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use installer::{PanelOwnershipHandoff, TransactionStore};
use pc_host::archive::{PANEL_AGENT_DIR, PANEL_SYNC, PROJECT_DIR, RUST_MANAGERS, RUST_SHARED};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::catalog::CatalogEntry;
use crate::errors::{failure_line, AgentError, Cause, UpdateError, UpdateState};
use crate::service::{optional_overlay, VersionAgent, COMPOSE_PROJECT, LEGACY_COMPOSE_PROJECT, PANEL_MANAGERS};
use crate::upstream::compare_versions;

use super::{
    argv, chained, compose_command, compose_up, copy2, is_symlink, override_exists, refuse, run, run_compose, stamp,
    state_dir, Failure, HostUpdater, Step, AGENT_RESTART, MAX_ARTIFACT,
};

/// The panel database files snapshotted before the new generation starts.
pub const PANEL_DB_FILES: [&str; 3] = ["panel.sqlite3", "panel.sqlite3-wal", "panel.sqlite3-shm"];
/// The class of the installer's journal-restore failure.
const OWNERSHIP_RECOVERY_FAILED: &str = "OwnershipRecoveryFailed";

/// `_update_panel_async(version, expected_current)`: validate under the agent lock, write the
/// `updating` marker and start the worker (inline when `synchronous`).
pub fn update_panel_async(
    updater: &HostUpdater,
    agent: &Arc<VersionAgent>,
    version: &str,
    expected: Option<&str>,
) -> Result<Value, AgentError> {
    let (entry, current) = {
        let _lock = agent.lock()?;
        let mut state = agent.load_state()?;
        let entry = agent.resolve("panel", version, &state)?;
        let present = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
        if entry.kind != "release" || !present(&entry.url) || !present(&entry.sha256) {
            return Err(AgentError::update("panel entry must be a release archive with a SHA-256"));
        }
        let data = VersionAgent::component_state(&state, "panel");
        let current = agent.panel_current(&data);
        let status = data.get("status").and_then(Value::as_str);
        if status == Some("updating") {
            return Err(AgentError::conflict("panel update is already running"));
        }
        if status == Some("rollback_failed") {
            return Err(UpdateError::rollback_failed(
                "panel has an unverified rollback; operator recovery is required",
            )
            .into());
        }
        if let Some(expected) = expected {
            if current.as_deref() != Some(expected) {
                return Err(AgentError::conflict("runtime version changed; reload the versions page"));
            }
        }
        if current.as_deref() == Some(version) {
            return Ok(json!({"component": "panel", "version": version, "changed": false}));
        }
        if let Some(current) = &current {
            if compare_versions(version, current) < 0 {
                // The database only migrates forward: going back is a full restore.
                return Err(AgentError::update("the panel cannot be downgraded; restore a backup instead"));
            }
        }
        preflight_compose_scope(agent).map_err(|failure| failure.into_update(|| "panel update failed".into()))?;
        if agent.rebuilding(&data) {
            return Err(AgentError::conflict("manager rebuild is running"));
        }
        let mut marker: Map<String, Value> = data
            .into_iter()
            .filter(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "status"
                        | "last_error"
                        | "pending_rebuild"
                        | "rebuild_error"
                        | "managers_rebuilt_at"
                        | "rebuilding_managers"
                )
            })
            .collect();
        marker.insert("version".into(), current.clone().map(Value::String).unwrap_or(Value::Null));
        marker.insert("status".into(), json!("updating"));
        marker.insert("started_at".into(), json!(agent.now_int()));
        let components = state.entry("components").or_insert_with(|| json!({}));
        if let Some(components) = components.as_object_mut() {
            components.insert("panel".into(), Value::Object(marker));
        }
        agent.save_state(&mut state).map_err(|err| AgentError::Internal(err.to_string()))?;
        (entry, current)
    };
    if agent.config.synchronous {
        panel_worker(updater, agent, &entry, current.as_deref()).map_err(AgentError::Update)?;
    } else {
        // The panel update restarts the panel, which drops the request that asked for it: it runs
        // in a thread and the request returns first.
        let (worker, agent_ref) = (updater.clone(), agent.clone());
        updater.spawn("panel-update", move || {
            let _ = panel_worker(&worker, &agent_ref, &entry, current.as_deref());
        })?;
    }
    Ok(json!({"component": "panel", "version": version, "changed": true, "async": true}))
}

pub(crate) fn legacy_unit_on_disk(root: &Path, unit: &str) -> io::Result<bool> {
    for directory in ["etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"] {
        match fs::symlink_metadata(root.join(directory).join(unit)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

/// Every running optional service must have its overlay in `PROXY_CONTROL_COMPOSE_FILES`.
/// Fleet v1 has no native replacement: reject its installed overlays and containers in either
/// historical Compose project rather than dropping its writer or persistent volumes.
pub fn preflight_compose_scope(agent: &VersionAgent) -> Step<()> {
    let Some(compose_dir) = agent.config.compose_dir.as_ref() else {
        return Err(refuse("Compose deployment is not configured"));
    };
    for unit in ["mtproxy-agent.service", "mtproxy-fleet-ingress.service"] {
        // systemd may not have reloaded after a unit file was installed; LoadState alone
        // can then report not-found while a legacy writer is present on disk.
        if legacy_unit_on_disk(Path::new("/"), unit)? {
            return Err(refuse(format!(
                "Fleet v1 unit {unit} is still installed; migrate its state explicitly before updating the panel"
            )));
        }
        let state =
            run(agent, &argv(&["systemctl", "show", "--property=LoadState", "--value", unit]), 30).map_err(|err| {
                Failure::Update(UpdateError::new("could not determine installed Fleet v1 units").caused_by(err.cause()))
            })?;
        match crate::py::strip(&state) {
            "not-found" => {}
            "loaded" | "masked" | "error" => {
                return Err(refuse(format!(
                    "Fleet v1 unit {unit} is still installed; migrate its state explicitly before updating the panel"
                )));
            }
            _ => return Err(refuse(format!("could not determine whether Fleet v1 unit {unit} is installed"))),
        }
    }
    for retired in ["compose.agent.yaml", "compose.fleet-central.yaml"] {
        let installed = match fs::symlink_metadata(compose_dir.join(retired)) {
            Ok(_) => true,
            Err(err) if err.kind() == io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
        if installed
            || agent
                .config
                .compose_files
                .iter()
                .any(|file| Path::new(file).file_name() == Some(std::ffi::OsStr::new(retired)))
        {
            return Err(refuse(format!(
                "Fleet v1 overlay {retired} is installed; migrate its state explicitly before updating the panel"
            )));
        }
    }
    let format = "{{.Label \"com.docker.compose.service\"}}";
    let project = agent.project();
    for candidate in [COMPOSE_PROJECT, LEGACY_COMPOSE_PROJECT] {
        let filter = format!("label=com.docker.compose.project={candidate}");
        let existing = run(agent, &argv(&["docker", "ps", "-a", "--filter", &filter, "--format", format]), 30)
            .map_err(|err| {
                Failure::Update(
                    UpdateError::new("could not determine existing Compose services").caused_by(err.cause()),
                )
            })?;
        for service in crate::py::splitlines(&existing) {
            let service = crate::py::strip(service);
            if matches!(service, "fleet-agent" | "fleet-ingress") {
                return Err(refuse(format!(
                    "Fleet v1 service {service} is still installed; migrate its state explicitly before updating the panel"
                )));
            }
        }
        if candidate != project {
            continue;
        }
        let running =
            run(agent, &argv(&["docker", "ps", "--filter", &filter, "--format", format]), 30).map_err(|err| {
                Failure::Update(UpdateError::new("could not determine running Compose services").caused_by(err.cause()))
            })?;
        for service in crate::py::splitlines(&running) {
            let service = crate::py::strip(service);
            if let Some(required) = optional_overlay(service) {
                if !agent.config.compose_files.iter().any(|file| file == required) {
                    return Err(refuse(format!(
                        "running service {service} requires {required} in PROXY_CONTROL_COMPOSE_FILES"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// `_panel_worker(entry, previous)`: runs the update, persists the verdict and never lets a
/// failure escape the thread (inline runs return it). Then the manager rebuild (when the panel is
/// healthy and recorded `ready`) and, as the very last step, the agent's restart.
pub fn panel_worker(
    updater: &HostUpdater,
    agent: &Arc<VersionAgent>,
    entry: &CatalogEntry,
    previous: Option<&str>,
) -> Result<(), UpdateError> {
    let mut pending: Vec<String> = Vec::new();
    let mut restart_agent = false;
    let error = match update_panel(updater, agent, entry, previous) {
        Ok((changed, restart)) => {
            pending = changed;
            restart_agent = restart;
            None
        }
        Err(Failure::Update(error)) => Some(error),
        Err(Failure::Other(cause)) => {
            Some(UpdateError::new(format!("panel update failed: {}", cause.message)).caused_by(cause))
        }
    };
    let now = agent.now_int();
    let verdict = match &error {
        None => json!({
            "version": entry.version,
            "kind": entry.kind,
            "source": entry.source,
            "url": entry.url,
            "sha256": entry.sha256,
            "updated_at": now,
            "previous_version": previous,
            "status": "ready",
            "pending_rebuild": pending,
        }),
        Some(error) => {
            let status = match error.state {
                UpdateState::RolledBack => "ready",
                UpdateState::RollbackFailed => "rollback_failed",
                UpdateState::UpdateFailed => "update_failed",
            };
            log::error!(target: "version_agent", "{}", failure_line("panel", &entry.version, error));
            json!({"version": previous, "kind": "release", "status": status, "last_error": error.message, "failed_at": now})
        }
    };
    let persisted = (|| -> Result<(), String> {
        let _lock = agent.lock().map_err(|e| e.message().to_string())?;
        let mut state = agent.load_state().map_err(|e| e.message)?;
        let components = state.entry("components").or_insert_with(|| json!({}));
        if let Some(components) = components.as_object_mut() {
            components.insert("panel".into(), verdict);
        }
        agent.save_state(&mut state).map_err(|e| e.to_string())
    })();
    if let Err(message) = persisted {
        crate::logging::print(&format!("panel state could not be persisted: {message}"));
        if agent.config.synchronous {
            return Err(UpdateError::new(message));
        }
    }
    if error.is_none() && !pending.is_empty() && agent.config.auto_rebuild_managers {
        // The panel is healthy and recorded as `ready`; whatever happens to the managers never
        // rolls it back — a failure is recorded as `rebuild_error`.
        if let Err(err) = super::managers::rebuild_managers(updater, agent, false) {
            crate::logging::print(&format!("manager rebuild could not run: {}", err.message()));
        }
    }
    if restart_agent {
        // The very last step: the agent's own tree changed with the release.
        if let Err(err) = run(agent, &argv(&AGENT_RESTART), 30) {
            crate::logging::print(&format!("restart could not be scheduled: {err}"));
        }
    }
    match error {
        Some(error) if agent.config.synchronous => Err(error),
        _ => Ok(()),
    }
}

/// `_update_panel(entry, previous)`: download and verify the release, unpack it into the staging
/// directory, sync and restart. Returns the changed managers and whether the agent's tree changed.
pub fn update_panel(
    updater: &HostUpdater,
    agent: &VersionAgent,
    entry: &CatalogEntry,
    previous: Option<&str>,
) -> Step<(Vec<String>, bool)> {
    let Some(compose_dir) = agent.config.compose_dir.clone() else {
        return Err(refuse("Compose deployment is not configured"));
    };
    let payload = updater.download(entry.url.as_deref().unwrap_or_default(), MAX_ARTIFACT)?;
    if Some(pc_host::fs::sha256_hex(&payload)) != entry.sha256 {
        return Err(refuse("panel artifact SHA-256 mismatch"));
    }
    let staging = state_dir(agent).join("staging");
    let _ = fs::remove_dir_all(&staging);
    let result = pc_host::archive::extract_panel_archive(&payload, &staging)
        .map_err(|err| refuse(err.0))
        .and_then(|()| sync_and_restart_panel(updater, agent, entry, previous, &staging, &compose_dir));
    let _ = fs::remove_dir_all(&staging);
    result
}

/// The installer root of the host (`/` for the production project directory).
pub fn installer_root(agent: &VersionAgent, compose_dir: &Path) -> PathBuf {
    if let Some(root) = &agent.config.installer_root {
        return root.clone();
    }
    if compose_dir == Path::new(PROJECT_DIR) {
        return PathBuf::from("/");
    }
    pc_host::fs::py_parent(compose_dir)
}

/// `_sync_and_restart_panel`: the installer and the agent must not mutate the same project
/// generation concurrently; the host operation lock is held until the rollback or the handoff
/// finishes. A busy lock is `another proxyctl operation is in progress`.
fn sync_and_restart_panel(
    updater: &HostUpdater,
    agent: &VersionAgent,
    entry: &CatalogEntry,
    previous: Option<&str>,
    staging: &Path,
    compose_dir: &Path,
) -> Step<(Vec<String>, bool)> {
    let root = installer_root(agent, compose_dir);
    let store = TransactionStore::new(&root)?;
    let _lock = pc_host::operation_lock(&root).map_err(|err| {
        if err.is_busy() {
            Failure::Update(UpdateError::new(err.message()))
        } else {
            Failure::from(err)
        }
    })?;
    sync_and_restart_panel_locked(updater, agent, entry, previous, staging, compose_dir, &store)
}

/// `_tree_hash(path)`: the content hash of a file or a directory tree (`__pycache__` and symlinks
/// ignored; a binary is hashed like any file); `None` when absent.
pub fn tree_hash(path: &Path) -> io::Result<Option<String>> {
    if !path.exists() || is_symlink(path) {
        return Ok(None);
    }
    let mut digest = Sha256::new();
    if path.is_file() {
        digest.update(fs::read(path)?);
    } else {
        hash_directory(path, path, &mut digest)?;
    }
    Ok(Some(hex(&digest.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `os.walk` top-down: a directory's files (sorted), then its subdirectories (sorted).
fn hash_directory(root: &Path, directory: &Path, digest: &mut Sha256) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(directory) else { return Ok(()) };
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut directories: Vec<(String, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        // `entry.is_dir()` follows symlinks; a symlinked directory is listed but never descended.
        if path.is_dir() {
            if name != "__pycache__" && !is_symlink(&path) {
                directories.push((name, path));
            }
        } else {
            files.push((name, path));
        }
    }
    files.sort();
    directories.sort();
    for (_, file) in files {
        if is_symlink(&file) {
            continue;
        }
        let relative = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().into_owned();
        digest.update(relative.as_bytes());
        digest.update(b"\0");
        digest.update(fs::read(&file)?);
        digest.update(b"\0");
    }
    for (_, child) in directories {
        hash_directory(root, &child, digest)?;
    }
    Ok(())
}

/// `_remove_entry(path)`: a file or symlink is unlinked, a directory removed with its tree.
fn remove_entry(path: &Path) -> io::Result<()> {
    if is_symlink(path) || path.is_file() {
        fs::remove_file(path)
    } else if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        Ok(())
    }
}

/// `shutil.copytree(source, target, symlinks=…)` with `copy2` for files and the directories'
/// permission bits and times copied last.
fn copy_tree(source: &Path, target: &Path, keep_symlinks: bool) -> io::Result<()> {
    fs::create_dir(target)?;
    let mut entries: Vec<_> = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let (from, to) = (entry.path(), target.join(entry.file_name()));
        if keep_symlinks && is_symlink(&from) {
            std::os::unix::fs::symlink(fs::read_link(&from)?, &to)?;
        } else if from.is_dir() {
            copy_tree(&from, &to, keep_symlinks)?;
        } else {
            copy2(&from, &to)?;
        }
    }
    let metadata = fs::metadata(source)?;
    fs::set_permissions(target, metadata.permissions())?;
    let times = fs::FileTimes::new().set_accessed(metadata.accessed()?).set_modified(metadata.modified()?);
    fs::File::open(target)?.set_times(times)
}

/// `_copy_entry(source, target)`: the staged entry into place (`copytree(symlinks=False)` or
/// `copy2`).
fn copy_entry(source: &Path, target: &Path) -> io::Result<()> {
    if source.is_dir() {
        copy_tree(source, target, false)
    } else {
        copy2(source, target)
    }
}

/// `shutil.move(source, target)`: a rename, or (across the unit's bind mounts) a copy that keeps
/// symlinks followed by the removal of the source. The running agent binary moves this way too;
/// unlinking a running executable is safe on Linux.
fn move_entry(source: &Path, target: &Path) -> io::Result<()> {
    match fs::rename(source, target) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
            if is_symlink(source) {
                std::os::unix::fs::symlink(fs::read_link(source)?, target)?;
                fs::remove_file(source)
            } else if source.is_dir() {
                copy_tree(source, target, true)?;
                fs::remove_dir_all(source)
            } else {
                copy2(source, target)?;
                fs::remove_file(source)
            }
        }
        Err(err) => Err(err),
    }
}

/// `_stop_panel_writers()`: stop them, then prove no container mounts the database volume any more
/// (a foreign container could; the agent refuses rather than stop its workload).
fn stop_panel_writers(agent: &VersionAgent) -> Step<()> {
    let args = ["stop", "panel"];
    run_compose(agent, &compose_command(agent, &args, override_exists(agent), true)?, 180)?;
    let filter = format!("volume={}", agent.panel_volume());
    let active = run(agent, &argv(&["docker", "ps", "--filter", &filter, "--format", "{{.ID}}"]), 30)?;
    if !crate::py::strip(&active).is_empty() {
        return Err(refuse("panel database volume still has active containers"));
    }
    Ok(())
}

/// `_panel_volume_dir()`: the database volume's mount point.
fn panel_volume_dir(agent: &VersionAgent) -> Step<PathBuf> {
    let volume = agent.panel_volume();
    let mountpoint = run(agent, &argv(&["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", &volume]), 30)?;
    let path = PathBuf::from(crate::py::strip(&mountpoint));
    if !path.is_absolute() || !path.is_dir() {
        return Err(refuse("panel volume mountpoint is missing"));
    }
    Ok(path)
}

/// `_copy_db_file(source, target)`: `copy2`, then the source's owner.
fn copy_db_file(updater: &HostUpdater, source: &Path, target: &Path) -> Step<()> {
    (updater.copy_db_file)(source, target)?;
    let metadata = fs::metadata(source)?;
    chown(target, metadata.uid(), metadata.gid())
}

fn chown(path: &Path, uid: u32, gid: u32) -> Step<()> {
    match std::os::unix::fs::chown(path, Some(uid), Some(gid)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            Err(Failure::Update(UpdateError::new("panel database copy could not keep its owner").caused_by(Cause {
                class: "PermissionError".into(),
                message: super::os_message(&err),
                stderr: None,
            })))
        }
        Err(err) => Err(err.into()),
    }
}

/// What the swap has done so far (what the rollback undoes).
#[derive(Default)]
struct Progress {
    synced: Vec<String>,
    /// The database files snapshotted (name → owner), once the snapshot is complete.
    db_saved: Option<BTreeMap<String, (u32, u32)>>,
    volume_dir: Option<PathBuf>,
    rollback_tag: Option<String>,
}

/// Where the swap's backups live.
struct Backups {
    tree: PathBuf,
    database: PathBuf,
}

/// The sync entries present in the release and where each lives on the host.
fn present_targets(agent: &VersionAgent, staging: &Path, compose_dir: &Path) -> Vec<(String, PathBuf)> {
    let mut targets: Vec<(String, PathBuf)> =
        PANEL_SYNC.iter().map(|name| (name.to_string(), compose_dir.join(name))).collect();
    targets.push((PANEL_AGENT_DIR.to_string(), agent.config.agent_dir.join(PANEL_AGENT_DIR)));
    targets.into_iter().filter(|(name, _)| staging.join(name).exists()).collect()
}

/// `_sync_and_restart_panel_locked`.
fn sync_and_restart_panel_locked(
    updater: &HostUpdater,
    agent: &VersionAgent,
    entry: &CatalogEntry,
    previous: Option<&str>,
    staging: &Path,
    compose_dir: &Path,
    store: &TransactionStore,
) -> Step<(Vec<String>, bool)> {
    preflight_compose_scope(agent)?;
    let present = present_targets(agent, staging, compose_dir);
    let names: Vec<&str> =
        present.iter().map(|(name, _)| name.as_str()).filter(|name| *name != PANEL_AGENT_DIR).collect();
    let mut handoff =
        PanelOwnershipHandoff::new(store, compose_dir, staging, &names, false, Some(agent.config.agent_dir.as_path()))?;
    handoff.prepare()?;
    for (_, target) in &present {
        if is_symlink(target) {
            return Err(refuse(format!("refusing to replace symlink {}", target.display())));
        }
    }
    let mut changed: BTreeMap<String, bool> = BTreeMap::new();
    for (name, target) in &present {
        changed.insert(name.clone(), tree_hash(target)? != tree_hash(&staging.join(name))?);
    }
    let is_changed = |name: &str| changed.get(name).copied().unwrap_or(false);
    let mut pending: Vec<String> =
        PANEL_MANAGERS.iter().filter(|name| is_changed(name)).map(|name| name.to_string()).collect();
    if is_changed(RUST_SHARED) {
        for name in RUST_MANAGERS {
            if changed.contains_key(*name) && !pending.iter().any(|known| known == name) {
                pending.push(name.to_string());
            }
        }
    }
    // The agent's own tree (its binary included). The installer is linked into the agent, nothing
    // is loaded from the project's `installer/` at run time any more.
    let agent_changed = is_changed(PANEL_AGENT_DIR);
    // A manual build can move :latest while the old container keeps running: refuse before
    // changing files if its immutable identity is unavailable.
    let container = agent.config.panel_container.clone();
    let running_image = run(agent, &argv(&["docker", "inspect", "--format", "{{.Image}}", &container]), 30)?;
    let running_image = crate::py::strip(&running_image).to_string();
    if !super::is_image_id(&running_image) {
        return Err(refuse("running panel image identity is unavailable"));
    }
    let backups = Backups {
        tree: state_dir(agent).join("backups").join("panel.previous"),
        database: state_dir(agent).join("backups").join("panel-db.previous"),
    };
    let _ = fs::remove_dir_all(&backups.tree);
    fs::create_dir_all(&backups.tree)?;
    let mut progress = Progress::default();
    let outcome = swap(
        updater,
        agent,
        entry,
        staging,
        compose_dir,
        &present,
        &backups,
        &running_image,
        &mut progress,
        &mut handoff,
    );
    let Err(exc) = outcome else { return Ok((pending, agent_changed)) };
    let restore = (|| -> Step<()> {
        restore_panel(updater, agent, compose_dir, &present, &backups, &progress)?;
        let running = agent.panel_container_version()?;
        if let Some(previous) = previous {
            if running != previous {
                let shown = if running.is_empty() { "nothing" } else { running.as_str() };
                return Err(refuse(format!("restored panel reports {shown}, expected {previous}")));
            }
        }
        Ok(())
    })();
    if let Err(rollback_exc) = restore {
        let error = UpdateError::rollback_failed(format!(
            "panel update failed ({exc}); restored generation could not be verified"
        ));
        return Err(Failure::Update(chained(chained(error, &rollback_exc), &exc)));
    }
    if exc.class() == OWNERSHIP_RECOVERY_FAILED {
        let error =
            UpdateError::rollback_failed("panel filesystem was restored but installer ownership recovery failed");
        return Err(Failure::Update(chained(error, &exc)));
    }
    let error =
        UpdateError::rolled_back(format!("panel update failed ({exc}); previous generation was restored and verified"));
    Err(Failure::Update(chained(error, &exc)))
}

/// The forward half: sync the trees, tag the running image, build, stop the writers, snapshot
/// the database, start the new generation, verify it and commit the ownership handoff.
#[allow(clippy::too_many_arguments)]
fn swap(
    updater: &HostUpdater,
    agent: &VersionAgent,
    entry: &CatalogEntry,
    staging: &Path,
    compose_dir: &Path,
    present: &[(String, PathBuf)],
    backups: &Backups,
    running_image: &str,
    progress: &mut Progress,
    handoff: &mut PanelOwnershipHandoff<'_>,
) -> Step<()> {
    for (name, target) in present {
        fs::create_dir_all(pc_host::fs::py_parent(target))?;
        if target.exists() {
            move_entry(target, &backups.tree.join(name))?;
        }
        progress.synced.push(name.clone());
        copy_entry(&staging.join(name), target)?;
    }
    pc_host::fs::fsync_directory(compose_dir)?;
    let tag = format!("{}:rollback-{}", agent.panel_image(), stamp(agent));
    run(agent, &argv(&["docker", "tag", running_image, &tag]), 60)?;
    progress.rollback_tag = Some(tag);
    run_compose(agent, &compose_command(agent, &["build", "panel"], override_exists(agent), true)?, 900)?;
    stop_panel_writers(agent)?;
    let volume_dir = panel_volume_dir(agent)?;
    progress.volume_dir = Some(volume_dir.clone());
    let _ = fs::remove_dir_all(&backups.database);
    fs::create_dir_all(&backups.database)?;
    let mut snapshot = BTreeMap::new();
    for name in PANEL_DB_FILES {
        let source = volume_dir.join(name);
        if source.is_file() {
            copy_db_file(updater, &source, &backups.database.join(name))?;
            let metadata = fs::metadata(&source)?;
            snapshot.insert(name.to_string(), (metadata.uid(), metadata.gid()));
        }
    }
    // A partial snapshot cannot replace the intact, still-stopped database.
    progress.db_saved = Some(snapshot);
    compose_up(agent, "panel")?;
    let running = agent.panel_container_version()?;
    if running != entry.version {
        let shown = if running.is_empty() { "nothing" } else { running.as_str() };
        return Err(refuse(format!("panel container reports {shown}, expected {}", entry.version)));
    }
    handoff.commit()?;
    Ok(())
}

/// `_restore_panel`: quiesce the failed generation (when the database was snapshotted), put the
/// previous trees back, then the database (anything else of the set goes), then the image.
fn restore_panel(
    updater: &HostUpdater,
    agent: &VersionAgent,
    compose_dir: &Path,
    present: &[(String, PathBuf)],
    backups: &Backups,
    progress: &Progress,
) -> Step<()> {
    let database = progress.db_saved.as_ref().zip(progress.volume_dir.as_ref());
    if database.is_some() {
        stop_panel_writers(agent)?;
    }
    for name in &progress.synced {
        let Some((_, target)) = present.iter().find(|(known, _)| known == name) else { continue };
        remove_entry(target)?;
        let backup = backups.tree.join(name);
        if backup.exists() || is_symlink(&backup) {
            move_entry(&backup, target)?;
        }
    }
    pc_host::fs::fsync_directory(compose_dir)?;
    if let Some((saved, volume_dir)) = database {
        // The new generation may have migrated the database and left a WAL of its own: the
        // previous files come back and anything else of the set goes.
        for name in PANEL_DB_FILES {
            match saved.get(name) {
                Some((uid, gid)) => {
                    copy_db_file(updater, &backups.database.join(name), &volume_dir.join(name))?;
                    chown(&volume_dir.join(name), *uid, *gid)?;
                }
                None => super::unlink_missing_ok(&volume_dir.join(name))?,
            }
        }
    }
    if let Some(tag) = &progress.rollback_tag {
        run(agent, &argv(&["docker", "tag", tag, &format!("{}:latest", agent.panel_image())]), 60)?;
        compose_up(agent, "panel")?;
    }
    // Before the image was tagged no runtime command ran: the still-running container is left
    // alone rather than recreated from an unrelated :latest.
    Ok(())
}
