//! Host binaries: naive (Caddy with the forward proxy) and mita (`_update_binary`,
//! `_fetch_binary`, `_build_caddy`, the config checks, the startup pin, the consumer overlay and the
//! restart of the service with its loaded slots).

use std::fs;
use std::path::{Path, PathBuf};

use crate::catalog::CatalogEntry;
use crate::runner::Command;
use crate::service::VersionAgent;

use super::{
    argv, atomic_write, chmod, compose_up, copyfile, is_symlink, mode_of, refuse, restore_copy, restore_file,
    rewrite_env_line, rolled_back, run, unlink_missing_ok, Failure, HostUpdater, Step, MAX_ARTIFACT,
};

/// `_fetch_binary`: download the catalog artifact, verify it, and unpack the named member if any.
pub fn fetch_binary(updater: &HostUpdater, component: &str, entry: &CatalogEntry) -> Step<Vec<u8>> {
    let url = entry.url.as_deref().unwrap_or_default();
    let payload = updater.download(url, MAX_ARTIFACT)?;
    if Some(pc_host::fs::sha256_hex(&payload)) != entry.sha256 {
        return Err(refuse(format!("{component} artifact SHA-256 mismatch")));
    }
    let Some(archive) = entry.archive.as_ref().filter(|a| !a.is_empty()) else { return Ok(payload) };
    let member = archive.get("member").and_then(|m| m.as_str()).filter(|m| !m.is_empty());
    let Some(member) = member else {
        return Err(refuse(format!("{component} archive entry must name a single member")));
    };
    let format = archive.get("format").and_then(|f| f.as_str());
    crate::artifacts::extract_member(&payload, format, member, crate::artifacts::MAX_MEMBER)
        .map_err(|err| refuse(format!("{component} archive: {err}")))
}

/// `_run_binary_config_checks`: the build checker (`CADDY_BIN`, `EXPECTED_CADDY_VERSION`) and, for
/// naive, `caddy adapt --validate` of the managed Caddyfile.
pub fn run_config_checks(
    agent: &VersionAgent,
    component: &str,
    binary: &Path,
    runtime_version: Option<&str>,
) -> Step<()> {
    if let Some(checker) = agent.config.checkers.get(component).filter(|c| !c.as_os_str().is_empty()) {
        let mut command =
            Command::new(&[checker.to_string_lossy().into_owned()]).env("CADDY_BIN", binary.to_string_lossy());
        if let Some(version) = runtime_version.filter(|v| !v.is_empty()) {
            command = command.env("EXPECTED_CADDY_VERSION", version);
        }
        agent.runner.run(&command)?;
    }
    if component == "naive" {
        if let Some(caddyfile) = agent.config.caddyfiles.get(component).filter(|c| !c.as_os_str().is_empty()) {
            let binary = binary.to_string_lossy().into_owned();
            let caddyfile = caddyfile.to_string_lossy().into_owned();
            agent.runner.run(&Command::new(&[
                binary.as_str(),
                "adapt",
                "--adapter",
                "caddyfile",
                "--validate",
                "--config",
                caddyfile.as_str(),
            ]))?;
        }
    }
    Ok(())
}

/// `_assert_binary_generation`.
fn assert_generation(target: &Path, expected: Option<&str>) -> Step<()> {
    let Some(expected) = expected.filter(|_| target.is_file()) else {
        return Err(refuse("binary generation is missing"));
    };
    if pc_host::fs::sha256_file(target)? != expected {
        return Err(refuse("binary generation readback did not match"));
    }
    Ok(())
}

/// `_write_pin`: keep the unit's startup check on the version just installed (it runs from
/// ExecStartPre without the agent's environment, so a stale pin would refuse the new build).
fn write_pin(agent: &VersionAgent, component: &str, runtime_version: Option<&str>) -> Step<()> {
    let (Some(pin), Some(version)) =
        (agent.config.version_pins.get(component), runtime_version.filter(|v| !v.is_empty()))
    else {
        return Ok(());
    };
    atomic_write(pin, format!("{version}\n").as_bytes(), 0o644)?;
    Ok(())
}

/// `_restore_pin`.
fn restore_pin(agent: &VersionAgent, component: &str, previous: Option<&str>) -> Step<()> {
    let Some(pin) = agent.config.version_pins.get(component) else { return Ok(()) };
    match previous {
        None => unlink_missing_ok(pin)?,
        Some(version) => atomic_write(pin, format!("{version}\n").as_bytes(), 0o644)?,
    }
    Ok(())
}

/// The pin's text, stripped (`pin.read_text().strip() if pin.exists() else None`).
fn read_pin(pin: &Path) -> Step<Option<String>> {
    if !pin.exists() {
        return Ok(None);
    }
    let text = String::from_utf8(fs::read(pin)?)
        .map_err(|_| Failure::other("UnicodeDecodeError", "'utf-8' codec can't decode the runtime pin"))?;
    Ok(Some(pc_common::pytext::strip(&text).to_string()))
}

/// `_assert_pin`.
fn assert_pin(agent: &VersionAgent, component: &str, expected: Option<&str>) -> Step<()> {
    let Some(pin) = agent.config.version_pins.get(component) else { return Ok(()) };
    if read_pin(pin)?.as_deref() != expected {
        return Err(refuse(format!("{component} runtime pin readback did not match")));
    }
    Ok(())
}

/// `_slot_units(service)`: loaded instances `<service>@<n>` (Mieru lanes) restart with the binary.
fn slot_units(agent: &VersionAgent, service: &str) -> Step<Vec<String>> {
    let pattern = format!("{service}@*.service");
    let listed = run(agent, &argv(&["systemctl", "list-units", "--plain", "--no-legend", &pattern]), 30)?;
    let mut units = Vec::new();
    for line in pc_common::pytext::splitlines(&listed) {
        let name = pc_common::pytext::split(line).first().copied().unwrap_or("");
        if name.starts_with(&format!("{service}@")) && name.ends_with(".service") {
            units.push(name.trim_end_matches(".service").to_string());
        }
    }
    Ok(units)
}

/// `_restart_service_and_slots`: restart, then `is-active` (a restart alone is not health).
fn restart_service_and_slots(agent: &VersionAgent, service: &str) -> Step<()> {
    run(agent, &argv(&["systemctl", "restart", service]), 120)?;
    run(agent, &argv(&["systemctl", "is-active", service]), 30)?;
    for unit in slot_units(agent, service)? {
        run(agent, &argv(&["systemctl", "restart", &unit]), 120)?;
        run(agent, &argv(&["systemctl", "is-active", &unit]), 30)?;
    }
    Ok(())
}

/// `_update_binary`: install `payload` (or the downloaded catalog artifact) as the component's
/// binary; returns its SHA-256. Every failure after the backup restores the previous binary, pin
/// and overlay, restarts and proves them, or reports the rollback as unverified.
pub fn update_binary(
    updater: &HostUpdater,
    agent: &VersionAgent,
    component: &str,
    entry: &CatalogEntry,
    payload: Option<Vec<u8>>,
    runtime_version: Option<&str>,
) -> Step<String> {
    let runtime_version: Option<String> =
        runtime_version.filter(|v| !v.is_empty()).map(String::from).or_else(|| entry.runtime_version.clone());
    let complete = entry.kind == "binary"
        && entry.url.as_deref().is_some_and(|u| !u.is_empty())
        && entry.sha256.as_deref().is_some_and(|s| !s.is_empty());
    if (payload.is_none() && !complete) || (payload.is_some() && !matches!(entry.kind.as_str(), "binary" | "build")) {
        return Err(refuse("binary catalog entry is incomplete"));
    }
    let (Some(target), Some(service)) =
        (agent.config.binary_paths.get(component), agent.config.service_names.get(component))
    else {
        return Err(refuse(format!("{component} runtime is not configured")));
    };
    let target: PathBuf = target.clone();
    if is_symlink(&target) {
        return Err(refuse(format!("refusing to replace symlink {}", target.display())));
    }
    if agent.config.version_pins.contains_key(component) && runtime_version.as_deref().is_none_or(str::is_empty) {
        return Err(refuse(format!(
            "{component} catalog entry must set runtime_version to keep the startup check in sync"
        )));
    }
    let consumer = agent.config.consumer_overlays.get(component).cloned();
    let payload = match payload {
        Some(payload) => payload,
        None => fetch_binary(updater, component, entry)?,
    };
    let installed = pc_host::fs::sha256_hex(&payload);
    let parent = pc_host::fs::py_parent(&target);
    fs::create_dir_all(&parent)?;
    let backup_dir = super::state_dir(agent).join("backups");
    fs::create_dir_all(&backup_dir)?;
    let backup = backup_dir.join(format!("{component}.previous"));
    let existed = target.exists();
    let previous_sha = if existed { Some(pc_host::fs::sha256_file(&target)?) } else { None };
    if existed {
        copyfile(&target, &backup)?;
        chmod(&backup, mode_of(&target)?)?;
    }
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let stage = target.with_file_name(format!(".{name}.proxy-control-new"));
    let pin = agent.config.version_pins.get(component).cloned();
    let previous_pin = match &pin {
        Some(pin) => read_pin(pin)?,
        None => None,
    };
    let mut previous_overlay: Option<Vec<u8>> = None;
    let mut overlay_touched = false;
    let outcome = (|| -> Step<()> {
        atomic_write(&stage, &payload, 0o755)?;
        run_config_checks(agent, component, &stage, runtime_version.as_deref())?;
        fs::rename(&stage, &target)?;
        pc_host::fs::fsync_directory(&parent)?;
        assert_generation(&target, Some(&installed))?;
        // Replacing the binary needs a restart: a reload re-reads the config but keeps the running
        // process, so the old build would stay live while state.json already claimed the new one.
        write_pin(agent, component, runtime_version.as_deref())?;
        assert_pin(agent, component, runtime_version.as_deref())?;
        if let Some((overlay, key, _)) = &consumer {
            // The consumer container pins the binary by digest through its env overlay; it
            // follows the new build before anything restarts.
            previous_overlay = rewrite_env_line(overlay, key, &installed)?;
            overlay_touched = true;
        }
        restart_service_and_slots(agent, service)?;
        if let Some((_, _, consumer_service)) = &consumer {
            compose_up(agent, consumer_service)?;
        }
        Ok(())
    })();
    let result = match outcome {
        Ok(()) => Ok(installed),
        Err(exc) => {
            let rollback = (|| -> Step<()> {
                if existed {
                    restore_copy(&backup, &target, mode_of(&backup)?)?;
                } else {
                    unlink_missing_ok(&target)?;
                }
                pc_host::fs::fsync_directory(&parent)?;
                restore_pin(agent, component, previous_pin.as_deref())?;
                assert_pin(agent, component, previous_pin.as_deref())?;
                if existed {
                    assert_generation(&target, previous_sha.as_deref())?;
                    run_config_checks(agent, component, &target, previous_pin.as_deref())?;
                }
                if let (Some((overlay, _, _)), true) = (&consumer, overlay_touched) {
                    restore_file(overlay, previous_overlay.as_deref(), 0o600)?;
                }
                restart_service_and_slots(agent, service)?;
                if let Some((_, _, consumer_service)) = &consumer {
                    compose_up(agent, consumer_service)?;
                }
                Ok(())
            })();
            Err(rolled_back(
                exc,
                rollback,
                format!("{component} update failed; restored generation could not be verified"),
                format!("{component} update failed; previous generation was restored and verified"),
            ))
        }
    };
    let _ = unlink_missing_ok(&stage);
    result
}

/// `_build_caddy`: build Caddy with the pinned forward-proxy commit from a digest-pinned builder
/// image (as `docker/Dockerfile.caddy-naive` and the installer do). Nothing on the host changes
/// until the build succeeded and reported the expected version. Returns the binary and its first
/// `version` line (the new pin).
pub fn build_caddy(_updater: &HostUpdater, agent: &VersionAgent, entry: &CatalogEntry) -> Step<(Vec<u8>, String)> {
    let Some(build) = entry.build.as_ref().filter(|b| !b.is_empty()) else {
        return Err(refuse("naive build entry is incomplete"));
    };
    let field = |key: &str| build.get(key).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let (builder, caddy_version, commit) =
        (field("builder_image"), field("caddy_version"), field("forwardproxy_commit"));
    let directory = &agent.config.caddy_build_dir;
    fs::create_dir_all(directory)?;
    chmod(directory, 0o700)?;
    let dockerfile = directory.join("Dockerfile");
    let text = format!(
        "# Generated by proxy-control version-agent; do not edit manually.\n\
         FROM {builder} AS builder\n\
         RUN xcaddy build v{caddy_version} \\\n    \
         --with github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@{commit}\n\
         FROM scratch\n\
         COPY --from=builder /usr/bin/caddy /caddy\n"
    );
    atomic_write(&dockerfile, text.as_bytes(), 0o600)?;
    let image = agent.config.caddy_image.clone();
    let (dockerfile_arg, directory_arg) =
        (dockerfile.to_string_lossy().into_owned(), directory.to_string_lossy().into_owned());
    run(agent, &argv(&["docker", "build", "-f", &dockerfile_arg, "-t", &image, &directory_arg]), 900)?;
    let container = run(agent, &argv(&["docker", "create", "--entrypoint", "/caddy", &image, "version"]), 60)?;
    let container = pc_common::pytext::strip(&container).to_string();
    let id_ok =
        (12..=64).contains(&container.len()) && container.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !id_ok {
        return Err(refuse("caddy build produced no container"));
    }
    let extracted = directory.join("caddy");
    let extracted_arg = extracted.to_string_lossy().into_owned();
    let copied = run(agent, &argv(&["docker", "cp", &format!("{container}:/caddy"), &extracted_arg]), 120);
    run(agent, &argv(&["docker", "rm", &container]), 60)?;
    copied?;
    let read = (|| -> Step<(Vec<u8>, String)> {
        let payload = fs::read(&extracted)?;
        chmod(&extracted, 0o755)?;
        let output = run(agent, &argv(&[&extracted_arg, "version"]), 30)?;
        let first = pc_common::pytext::splitlines(pc_common::pytext::strip(&output))
            .first()
            .map(|l| pc_common::pytext::strip(l).to_string());
        Ok((payload, first.unwrap_or_default()))
    })();
    let _ = unlink_missing_ok(&extracted);
    let (payload, runtime_version) = read?;
    if !runtime_version.starts_with(&format!("v{caddy_version} ")) {
        let reported = if runtime_version.is_empty() { "nothing" } else { runtime_version.as_str() };
        return Err(refuse(format!("built Caddy reports {reported}, expected v{caddy_version}")));
    }
    Ok((payload, runtime_version))
}
