//! Retires the unused Fleet v1 overlays a 3.x installation left in the project directory.
//!
//! The 4.0 release no longer ships `compose.agent.yaml` / `compose.fleet-central.yaml`, and the
//! version-agent refuses a panel update while either file is installed. On a host that never
//! used Fleet v1 they are inert leftovers; on a host installed through the engine the installer
//! journal additionally owns them (`core.runtime`), so deleting them by hand reads as drift.
//! This step proves the overlays are unused, drops them from the journal exactly as the panel
//! ownership handoff rebases it, and only then moves the files out of the project directory. The
//! files are kept, not deleted.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pc_host::archive::PROJECT_DIR;
use pc_host::fs::sha256_hex;
use serde_json::Value;

use super::compose::{Model, NEW, OLD};
use super::{read_env, strings, Host, Result};
use crate::handoff::{read_active_state, write_rebased, CORE_ACTION};
use crate::journal::Checkpoint;
use crate::store::TransactionStore;

pub(super) const OVERLAYS: [&str; 2] = ["compose.agent.yaml", "compose.fleet-central.yaml"];
const UNITS: [&str; 2] = ["mtproxy-agent.service", "mtproxy-fleet-ingress.service"];
const UNIT_DIRS: [&str; 3] = ["etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system"];
/// Where retired overlays are kept (inside the version-agent's writable state tree).
pub(super) const KEPT_DIR: &str = "/var/lib/proxy-control/retired";

fn in_use(name: &str, why: impl std::fmt::Display) -> String {
    format!("Fleet v1 overlay {name} is in use ({why}); migrate its state explicitly before updating the panel")
}

/// Refuses unless nothing of Fleet v1 runs or is configured: no unit, container, volume, Compose
/// reference or `FLEET_*` setting. The overlay file alone is not use.
fn ensure_unused(host: &Host<'_>, model: &Model, project: &Path, present: &[&str]) -> Result<()> {
    let first = present[0];
    for name in present {
        if fs::symlink_metadata(project.join(name)).map_err(|e| e.to_string())?.file_type().is_symlink() {
            return Err(format!("Fleet v1 overlay {name} is a symlink; refusing to retire it"));
        }
        if model.files.iter().any(|file| Path::new(file).file_name().is_some_and(|base| base == *name)) {
            return Err(in_use(name, "listed in PROXY_CONTROL_COMPOSE_FILES"));
        }
    }
    for unit in UNITS {
        for directory in UNIT_DIRS {
            if fs::symlink_metadata(host.root.join(directory).join(unit)).is_ok() {
                return Err(in_use(first, format!("unit {unit} is installed")));
            }
        }
    }
    for project_name in [NEW, OLD] {
        let services = host
            .query(&strings(&[
                "docker",
                "ps",
                "-a",
                "--filter",
                &format!("label=com.docker.compose.project={project_name}"),
                "--format",
                "{{.Label \"com.docker.compose.service\"}}",
            ]))
            .map_err(|_| "could not determine existing Compose services")?;
        if services.lines().any(|service| matches!(service.trim(), "fleet-agent" | "fleet-ingress")) {
            return Err(in_use(first, "a Fleet v1 container exists"));
        }
    }
    let volumes = host
        .query(&strings(&["docker", "volume", "ls", "--format", "{{.Name}}"]))
        .map_err(|_| "could not determine existing Docker volumes")?;
    if volumes.lines().any(|volume| volume.to_ascii_lowercase().contains("fleet")) {
        return Err(in_use(first, "a Fleet volume exists"));
    }
    let mut settings = read_env(&host.env)?;
    let dotenv = project.join(".env");
    if dotenv.is_file() {
        settings.extend(read_env(&dotenv)?);
    }
    if let Some(key) = settings.keys().find(|key| key.starts_with("FLEET_")) {
        return Err(in_use(first, format!("{key} is configured")));
    }
    Ok(())
}

/// Moves the overlays to `kept`: copies are verified before any original is removed, and a
/// failure puts every removed original back.
fn move_files(project: &Path, names: &[&str], kept: &Path) -> Result<()> {
    fs::create_dir_all(kept).map_err(|e| format!("could not create {}: {e}", kept.display()))?;
    fs::set_permissions(kept, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let mut contents = Vec::new();
    for name in names {
        let data = fs::read(project.join(name)).map_err(|e| format!("could not read {name}: {e}"))?;
        let copy = kept.join(name);
        pc_host::fs::atomic_write(&copy, &data, 0o600, None).map_err(|e| format!("could not keep {name}: {e}"))?;
        if fs::read(&copy).map_err(|e| e.to_string())? != data {
            return Err(format!("the kept copy of {name} differs from the original"));
        }
        contents.push(data);
    }
    let mut removed = 0;
    for name in names {
        if let Err(error) = fs::remove_file(project.join(name)) {
            for (name, data) in names.iter().zip(&contents).take(removed) {
                let _ = pc_host::fs::atomic_write(&project.join(name), data, 0o644, None);
            }
            return Err(format!("could not remove {name}: {error}"));
        }
        removed += 1;
    }
    Ok(())
}

/// Retires the unused Fleet v1 overlays of `project`; returns a report line, empty when none were
/// installed.
pub(super) fn retire_unused_overlays(host: &Host<'_>, project: &Path, model: &Model) -> Result<String> {
    let present: Vec<&str> =
        OVERLAYS.iter().copied().filter(|name| fs::symlink_metadata(project.join(name)).is_ok()).collect();
    if present.is_empty() {
        return Ok(String::new());
    }
    ensure_unused(host, model, project, &present)?;
    let store = TransactionStore::new(&host.root).map_err(|e| e.to_string())?;
    let mut journal = None;
    if store.state_exists() {
        if project != host.path(PROJECT_DIR)? {
            return Err("panel project path does not match Core ownership".into());
        }
        let previous = read_active_state(&store, "the installer journal is not an active installer transaction")
            .map_err(|e| e.to_string())?;
        let core = previous.checkpoint(CORE_ACTION).ok_or("the Core checkpoint is unavailable")?.clone();
        let mut ownership = core.ownership.clone();
        let mut data = core.data.clone();
        let mut changed = false;
        for name in &present {
            let key = format!("{PROJECT_DIR}/{name}");
            if let Some(entry) = ownership.remove(&key) {
                let bytes = fs::read(project.join(name)).map_err(|e| format!("could not read {name}: {e}"))?;
                if sha256_hex(&bytes) != entry.sha256 {
                    return Err(format!("owned file drifted: {key}"));
                }
                changed = true;
            }
            if let Some(Value::Object(declared)) = data.get_mut("ownership") {
                declared.remove(&key);
            }
        }
        if changed {
            let mut next = previous.clone();
            next.with_checkpoint(Checkpoint { data, ownership, ..core });
            write_rebased(
                &store,
                &previous,
                &next,
                "Fleet v1 overlay retirement failed and the journal could not be restored",
            )
            .map_err(|e| e.message())?;
            journal = Some((previous, next));
        }
    }
    let stamp = pc_host::fs::token_hex::<8>();
    let kept: PathBuf = host.path(KEPT_DIR)?.join(format!("fleet-v1-{stamp}"));
    if let Err(error) = move_files(project, &present, &kept) {
        if let Some((previous, next)) = &journal {
            write_rebased(
                &store,
                next,
                previous,
                "Fleet v1 overlay retirement failed and the journal could not be restored",
            )
            .map_err(|e| format!("{error}; JOURNAL RESTORE FAILED: {}", e.message()))?;
        }
        return Err(format!("could not retire the unused Fleet v1 overlays: {error}"));
    }
    Ok(format!("retired the unused Fleet v1 overlays {} (kept in {KEPT_DIR}/fleet-v1-{stamp})\n", present.join(" ")))
}
