//! Telemt (`_update_telemt`): the `mtproxy` service's image pinned in the version override —
//! a registry image by digest (`image`), or a local image built from the pinned base image and the
//! SHA-256-pinned upstream binary (`build`). The image is verified running and healthy; a failure
//! puts the previous override back and proves the previous image healthy again.

use std::fs;
use std::time::{Duration, Instant};

use crate::catalog::CatalogEntry;
use crate::service::VersionAgent;

use super::{
    argv, atomic_write, chmod, compose_command, override_path, override_with, read_if_exists, read_override, refuse,
    rolled_back, run, run_compose, state_dir, unlink_missing_ok, HostUpdater, Step,
};

/// `TELEMT_LOCAL_REPOSITORY`: the tag of locally built images.
pub const TELEMT_LOCAL_REPOSITORY: &str = "proxy-control-telemt";

/// `_fetch_telemt_binary`: download the upstream binary and prove it is the pinned one; it is
/// never run on the host, only copied into the image.
fn fetch_telemt_binary(updater: &HostUpdater, entry: &CatalogEntry) -> Step<Vec<u8>> {
    if updater.system != "linux" || !updater.is_x86_64() {
        return Err(refuse("the Telemt release binary is Linux x86_64 only"));
    }
    let payload = updater.download(entry.url.as_deref().unwrap_or_default(), updater.telemt_binary_max)?;
    if payload.len() as u64 > updater.telemt_binary_max {
        return Err(refuse("telemt artifact is too large"));
    }
    if Some(pc_host::fs::sha256_hex(&payload)) != entry.sha256 {
        return Err(refuse("telemt artifact SHA-256 mismatch"));
    }
    Ok(payload)
}

/// `_build_telemt_image`: `docker build` of the pinned base image plus the verified binary, from a
/// Dockerfile generated out of fields the catalog validated.
fn build_telemt_image(agent: &VersionAgent, entry: &CatalogEntry, binary: &[u8], tag: &str) -> Step<()> {
    let directory = state_dir(agent).join("telemt-build");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory)?;
    chmod(&directory, 0o700)?;
    atomic_write(&directory.join("telemt"), binary, 0o755)?;
    let dockerfile = format!(
        "FROM {}\nCOPY telemt /usr/local/bin/telemt\nRUN chmod 0755 /usr/local/bin/telemt\n\
         LABEL org.proxy-control.telemt.version=\"{}\" org.proxy-control.telemt.sha256=\"{}\"\n",
        entry.base_image.as_deref().unwrap_or_default(),
        entry.version,
        entry.sha256.as_deref().unwrap_or_default(),
    );
    atomic_write(&directory.join("Dockerfile"), dockerfile.as_bytes(), 0o600)?;
    run(agent, &argv(&["docker", "build", "-t", tag, &directory.to_string_lossy()]), 900)?;
    Ok(())
}

/// `_prune_telemt_images`: remove older locally built images (best effort, never fatal).
fn prune_telemt_images(agent: &VersionAgent, keep: &[&str]) {
    let format = "{{.Repository}}:{{.Tag}}";
    let Ok(listing) = run(agent, &argv(&["docker", "image", "ls", "--format", format, TELEMT_LOCAL_REPOSITORY]), 30)
    else {
        return;
    };
    for image in pc_common::pytext::split(&listing) {
        if image.starts_with(&format!("{TELEMT_LOCAL_REPOSITORY}:")) && !keep.contains(&image) {
            // An image still in use stays.
            let _ = run(agent, &argv(&["docker", "image", "rm", image]), 60);
        }
    }
}

/// `_inspect_telemt_image`: the image the container was created from.
fn inspect_telemt_image(agent: &VersionAgent) -> Step<String> {
    let container = agent.config.telemt_container.clone();
    let image = run(agent, &argv(&["docker", "inspect", "--format", "{{.Config.Image}}", &container]), 30)?;
    let image = pc_common::pytext::strip(&image).to_string();
    if image.is_empty() {
        return Err(refuse("Telemt image readback was empty"));
    }
    Ok(image)
}

/// `_verify_telemt_generation`: the container runs `expected`, and its health check turns
/// `healthy` within the health timeout.
fn verify_telemt_generation(updater: &HostUpdater, agent: &VersionAgent, expected: &str) -> Step<()> {
    if inspect_telemt_image(agent)? != expected {
        return Err(refuse("Telemt image readback did not match the selected generation"));
    }
    let timeout = agent.config.health_timeout.max(0.0);
    let deadline = Instant::now() + Duration::from_secs_f64(if timeout.is_finite() { timeout } else { 0.0 });
    let container = agent.config.telemt_container.clone();
    let status = loop {
        let status = run(agent, &argv(&["docker", "inspect", "--format", "{{.State.Health.Status}}", &container]), 30)?;
        let status = pc_common::pytext::strip(&status).to_string();
        if status == "healthy" {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now()).as_secs_f64();
        if remaining <= 0.0 {
            break status;
        }
        (updater.sleep)(remaining.min(1.0));
    };
    let status = if status.is_empty() { "unknown".to_string() } else { status };
    Err(refuse(format!("Telemt health did not become healthy: {status}")))
}

/// `_update_telemt(entry)`.
pub fn update_telemt(updater: &HostUpdater, agent: &VersionAgent, entry: &CatalogEntry) -> Step<()> {
    let build = entry.kind == "build";
    let present = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
    let target = if build {
        if !(present(&entry.base_image) && present(&entry.url) && present(&entry.sha256)) {
            return Err(refuse("Telemt catalog entry is incomplete"));
        }
        let sha = entry.sha256.as_deref().unwrap_or_default();
        format!("{TELEMT_LOCAL_REPOSITORY}:{}-{}", entry.version, &sha[..sha.len().min(12)])
    } else if entry.kind == "image" && present(&entry.image) {
        entry.image.clone().unwrap_or_default()
    } else {
        return Err(refuse("Telemt catalog entry is incomplete"));
    };
    let Some(override_file) = override_path(agent) else {
        return Err(refuse("Telemt Compose deployment is not configured"));
    };
    // Everything that can refuse (architecture, download, SHA-256) runs before the host changes.
    let binary = if build { Some(fetch_telemt_binary(updater, entry)?) } else { None };
    let previous = read_if_exists(&override_file)?;
    let previous_image = inspect_telemt_image(agent)?;
    let content = override_with(&read_override(&override_file)?, "mtproxy", &[format!("    image: {target}")]);
    // Every Compose call carries the protocol overlays: the model includes their files, whose
    // required variables live only there.
    let outcome = (|| -> Step<()> {
        if let Some(binary) = &binary {
            build_telemt_image(agent, entry, binary, &target)?;
        }
        atomic_write(&override_file, content.as_bytes(), 0o640)?;
        if !build {
            // A locally built tag is not in any registry.
            run_compose(agent, &compose_command(agent, &["pull", "mtproxy"], true, true)?, 900)?;
        }
        run_compose(agent, &compose_command(agent, &["up", "-d", "--no-deps", "mtproxy"], true, true)?, 300)?;
        verify_telemt_generation(updater, agent, &target)
    })();
    if let Err(exc) = outcome {
        let rollback = (|| -> Step<()> {
            let command = match &previous {
                None => {
                    unlink_missing_ok(&override_file)?;
                    compose_command(agent, &["up", "-d", "--no-deps", "mtproxy"], false, true)?
                }
                Some(data) => {
                    atomic_write(&override_file, data, 0o640)?;
                    compose_command(agent, &["up", "-d", "--no-deps", "mtproxy"], true, true)?
                }
            };
            run_compose(agent, &command, 300)?;
            verify_telemt_generation(updater, agent, &previous_image)
        })();
        return Err(rolled_back(
            exc,
            rollback,
            "Telemt update failed; restored generation could not be verified".into(),
            "Telemt update failed; previous generation was restored and verified".into(),
        ));
    }
    if build {
        prune_telemt_images(agent, &[&target, &previous_image]);
    }
    Ok(())
}
