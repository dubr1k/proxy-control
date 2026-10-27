//! Manager images: the AmneziaWG and TrustTunnel runtimes pinned as Compose build args in the
//! version override (`_update_manager`), and the rebuild of the managers a panel update changed
//! (`rebuild_managers`, `_rebuild_worker`, `_rebuild_services`, `_wait_healthy`).

use std::sync::Arc;

use serde_json::{json, Value};

use crate::catalog::CatalogEntry;
use crate::errors::AgentError;
use crate::service::{manager_build, manager_services, pending_list, VersionAgent};

use super::{
    argv, atomic_write, compose_command, override_exists, override_path, override_with, read_if_exists, read_override,
    refuse, rolled_back, run, run_compose, stamp, unlink_missing_ok, HostUpdater, Step,
};

/// `_wait_healthy(services)`: every container of every service `healthy` (or `running` without a
/// health check), polled every 2 s up to `manager_health_timeout`.
pub fn wait_healthy(updater: &HostUpdater, agent: &VersionAgent, services: &[String]) -> Step<()> {
    let mut waited = 0.0;
    loop {
        let mut states = Vec::new();
        for service in services {
            let containers = agent.service_containers(service)?;
            if containers.is_empty() {
                states.push(format!("{service}=missing"));
                continue;
            }
            for container in containers {
                let format = "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}";
                let status = run(agent, &argv(&["docker", "inspect", "--format", format, &container]), 30)?;
                let status = pc_common::pytext::strip(&status);
                if status != "healthy" && status != "running" {
                    states.push(format!("{service}={}", if status.is_empty() { "unknown" } else { status }));
                }
            }
        }
        if states.is_empty() {
            return Ok(());
        }
        if waited >= agent.config.manager_health_timeout {
            return Err(refuse(format!("not healthy: {}", states.join(", "))));
        }
        (updater.sleep)(2.0);
        waited += 2.0;
    }
}

/// `_update_manager(component, entry, previous_version)`: rebuild the AmneziaWG or TrustTunnel
/// manager's image with another upstream version. The pinned version goes into the shared override
/// as build args, so every later rebuild keeps it. A failed build, start, version readback or
/// health check puts the previous override and image back and proves the previous version runs.
pub fn update_manager(
    updater: &HostUpdater,
    agent: &VersionAgent,
    component: &str,
    entry: &CatalogEntry,
    previous_version: Option<&str>,
) -> Step<()> {
    let Some((service, container, _, _)) = manager_build(component) else {
        return Err(refuse("unsupported component"));
    };
    let args: Vec<(&str, String)> = if component == "amneziawg" {
        let commit = entry.build.as_ref().and_then(|b| b.get("commit")).and_then(Value::as_str).unwrap_or_default();
        if commit.is_empty() {
            return Err(refuse("AmneziaWG catalog entry is incomplete"));
        }
        vec![("AWG_GO_VERSION", entry.version.clone()), ("AWG_GO_COMMIT", commit.to_string())]
    } else {
        if !updater.is_x86_64() {
            return Err(refuse("the TrustTunnel release archive is pinned for x86_64 only"));
        }
        let sha = entry.sha256.clone().unwrap_or_default();
        if sha.is_empty() {
            return Err(refuse("TrustTunnel catalog entry is incomplete"));
        }
        vec![("TT_VERSION", format!("v{}", entry.version)), ("TT_SHA256_X86_64", sha)]
    };
    let Some(override_file) = override_path(agent) else {
        return Err(refuse("Compose deployment is not configured"));
    };
    let previous = read_if_exists(&override_file)?;
    let project = agent.project();
    let image = run(agent, &argv(&["docker", "inspect", "--format", "{{.Image}}", container]), 30)?;
    let image = pc_common::pytext::strip(&image).to_string();
    if !super::is_image_id(&image) {
        return Err(refuse(format!("{service} image identity is unavailable")));
    }
    let rollback_tag = format!("{project}-{service}:rollback-{}", stamp(agent));
    run(agent, &argv(&["docker", "tag", &image, &rollback_tag]), 60)?;
    let mut block = vec!["    build:".to_string(), "      args:".to_string()];
    block.extend(args.iter().map(|(key, value)| format!("        {key}: \"{value}\"")));
    let outcome = (|| -> Step<()> {
        let content = override_with(&read_override(&override_file)?, service, &block);
        atomic_write(&override_file, content.as_bytes(), 0o640)?;
        // Under the panel's 1200 s wait for the verdict.
        let command = compose_command(agent, &["up", "-d", "--build", "--no-deps", service], true, true)?;
        run_compose(agent, &command, 1080)?;
        wait_healthy(updater, agent, &[service.to_string()])?;
        let running = agent.manager_version(component);
        if running.as_deref() != Some(entry.version.as_str()) {
            let shown = running.unwrap_or_else(|| "no version".into());
            return Err(refuse(format!("{service} reports {shown} after the rebuild")));
        }
        Ok(())
    })();
    let Err(exc) = outcome else { return Ok(()) };
    let rollback = (|| -> Step<()> {
        match &previous {
            None => unlink_missing_ok(&override_file)?,
            Some(data) => atomic_write(&override_file, data, 0o640)?,
        }
        run(agent, &argv(&["docker", "tag", &rollback_tag, &format!("{project}-{service}:latest")]), 60)?;
        let command =
            compose_command(agent, &["up", "-d", "--no-build", "--no-deps", service], override_file.exists(), true)?;
        run_compose(agent, &command, 300)?;
        wait_healthy(updater, agent, &[service.to_string()])?;
        if let Some(previous_version) = previous_version {
            if agent.manager_version(component).as_deref() != Some(previous_version) {
                return Err(refuse(format!("{service} did not come back on {previous_version}")));
            }
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

/// `rebuild_managers(background=…)`: rebuild the service-backed managers in `pending_rebuild` with
/// one Compose call (same env files, overlays and version override as the panel build). A failure
/// restores the saved images, leaves the list and is recorded as `rebuild_error`; it never rolls
/// the healthy panel back.
pub fn rebuild_managers(
    updater: &HostUpdater,
    agent: &Arc<VersionAgent>,
    background: bool,
) -> Result<Value, AgentError> {
    let services = {
        let _lock = agent.lock()?;
        let mut state = agent.load_state()?;
        let services = agent.rebuild_preflight(&state)?;
        if services.is_empty() {
            return agent.managers_state();
        }
        let mut panel = VersionAgent::component_state(&state, "panel");
        panel.insert("rebuilding_managers".into(), json!(agent.now_int()));
        let components = state.entry("components").or_insert_with(|| json!({}));
        if let Some(components) = components.as_object_mut() {
            components.insert("panel".into(), Value::Object(panel));
        }
        agent.save_state(&mut state).map_err(|err| AgentError::Internal(err.to_string()))?;
        services
    };
    if background && !agent.config.synchronous {
        let (worker, agent_ref) = (updater.clone(), agent.clone());
        updater.spawn("managers-rebuild", move || rebuild_worker(&worker, &agent_ref, &services))?;
    } else {
        rebuild_worker(updater, agent, &services);
    }
    agent.managers_state()
}

/// `_rebuild_worker`: run the rebuild and record the verdict (never raised into the caller).
pub fn rebuild_worker(updater: &HostUpdater, agent: &VersionAgent, services: &[String]) {
    let error = rebuild_services(updater, agent, services).err().map(|exc| format!("manager rebuild failed: {exc}"));
    let persisted = (|| -> Result<(), String> {
        let _lock = agent.lock().map_err(|e| e.message().to_string())?;
        let mut state = agent.load_state().map_err(|e| e.message)?;
        let mut panel = VersionAgent::component_state(&state, "panel");
        panel.remove("rebuilding_managers");
        match &error {
            None => {
                let left: Vec<Value> = pending_list(panel.get("pending_rebuild"))
                    .into_iter()
                    .filter(|name| !name.as_str().is_some_and(|n| manager_services(n).is_some()))
                    .collect();
                panel.insert("pending_rebuild".into(), Value::Array(left));
                panel.remove("rebuild_error");
                panel.insert("managers_rebuilt_at".into(), json!(agent.now_int()));
            }
            Some(message) => {
                panel.insert("rebuild_error".into(), json!(message));
            }
        }
        let components = state.entry("components").or_insert_with(|| json!({}));
        if let Some(components) = components.as_object_mut() {
            components.insert("panel".into(), Value::Object(panel));
        }
        agent.save_state(&mut state).map_err(|e| e.to_string())
    })();
    if let Err(message) = persisted {
        crate::logging::print(&format!("manager rebuild state could not be persisted: {message}"));
    }
    if let Some(message) = &error {
        log::error!(target: "version_agent", "{message}");
    }
}

/// `_rebuild_services(services)`: save each running image under a rollback tag, build and recreate
/// all of them at once, wait for health; on failure put the saved images back.
pub fn rebuild_services(updater: &HostUpdater, agent: &VersionAgent, services: &[String]) -> Step<()> {
    let stamp = stamp(agent);
    let project = agent.project();
    let mut saved: Vec<(String, String)> = Vec::new();
    let mut running: Vec<String> = Vec::new();
    for service in services {
        let containers = agent.service_containers(service)?;
        if let Some(container) = containers.first() {
            let image = run(agent, &argv(&["docker", "inspect", "--format", "{{.Image}}", container]), 30)?;
            let image = pc_common::pytext::strip(&image);
            if super::is_image_id(image) {
                let tag = format!("{project}-{service}:rollback-{stamp}");
                run(agent, &argv(&["docker", "tag", image, &tag]), 60)?;
                saved.push((service.clone(), tag));
                running.push(service.clone());
            }
        }
    }
    let mut args = vec!["up", "-d", "--build", "--no-deps"];
    args.extend(services.iter().map(String::as_str));
    let outcome = (|| -> Step<()> {
        run_compose(agent, &compose_command(agent, &args, override_exists(agent), true)?, 900)?;
        wait_healthy(updater, agent, services)
    })();
    if let Err(exc) = outcome {
        let restore = (|| -> Step<()> {
            for (service, tag) in &saved {
                run(agent, &argv(&["docker", "tag", tag, &format!("{project}-{service}:latest")]), 60)?;
            }
            if !running.is_empty() {
                let mut args = vec!["up", "-d", "--no-build", "--no-deps"];
                args.extend(running.iter().map(String::as_str));
                run_compose(agent, &compose_command(agent, &args, override_exists(agent), true)?, 300)?;
            }
            Ok(())
        })();
        if let Err(restore_exc) = restore {
            crate::logging::print(&format!("manager images could not be restored: {restore_exc}"));
        }
        return Err(exc);
    }
    Ok(())
}
