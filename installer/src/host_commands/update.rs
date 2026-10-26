use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::compose::{Model, NEW, OLD};
use super::{agent, read_env, strings, Host, Result};

fn panel(document: &Value) -> Result<&Value> {
    document
        .pointer("/components/panel")
        .filter(|v| v.is_object())
        .ok_or_else(|| "version-agent panel state is unavailable".into())
}

fn pending(panel: &Value) -> Result<Vec<String>> {
    match panel.get("pending_rebuild") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| "invalid pending_rebuild entry".into()))
            .collect(),
        _ => Err("invalid pending_rebuild state".into()),
    }
}

fn scope(host: &Host<'_>, model: &Model, project: &str) -> Result<()> {
    let running = host
        .query(&strings(&[
            "docker",
            "ps",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "{{.Label \"com.docker.compose.service\"}}",
        ]))
        .map_err(|_| "could not determine running Compose services")?;
    for service in running.lines() {
        let file = match service {
            "mcp" => "compose.mcp.yaml",
            "naive-manager" => "compose.naive.yaml",
            "mieru-manager" => "compose.mieru.yaml",
            "xray-router" | "xray-router-ingress" => "compose.xray-router.yaml",
            "awg-manager" => "compose.amneziawg.yaml",
            "trusttunnel-manager" => "compose.trusttunnel.yaml",
            "fleet-agent" | "fleet-ingress" => {
                return Err("Fleet v1 is retired: migrate every v1 node to v2 before the 4.0 update".into())
            }
            _ => continue,
        };
        if !model.has(file) {
            return Err(format!("running service {service} requires {file} in PROXY_CONTROL_COMPOSE_FILES"));
        }
    }
    Ok(())
}

const MANAGERS: &[(&str, &str, &str)] = &[
    ("mieru_manager", "compose.mieru.yaml", "mieru-manager"),
    ("naive_manager", "compose.naive.yaml", "naive-manager"),
    ("xray_router_manager", "compose.xray-router.yaml", "xray-router"),
    ("awg_manager", "compose.amneziawg.yaml", "awg-manager"),
    ("trusttunnel_manager", "compose.trusttunnel.yaml", "trusttunnel-manager"),
    ("mcp_server", "compose.mcp.yaml", "mcp"),
];

fn rebuild(host: &Host<'_>, model: &Model, project: &str, pending: &[String]) -> Result<()> {
    let mut services = Vec::new();
    let mut acked = Vec::new();
    for name in pending {
        if let Some((name, file, service)) = MANAGERS.iter().find(|(manager, _, _)| manager == name) {
            if model.has(file) {
                services.push(service.to_string());
                acked.push(name.to_string());
            }
        }
    }
    // Reconcile an enabled MCP even if an older generation omitted it from its pending list.
    if model.has("compose.mcp.yaml") && !services.iter().any(|name| name == "mcp") {
        services.push("mcp".into());
        acked.push("mcp_server".into());
    }
    if model.has("compose.xray-router.yaml") {
        services.push("xray-router-ingress".into());
    }
    if services.is_empty() {
        return Ok(());
    }
    let _lock = pc_host::operation_lock(&host.root).map_err(|e| e.to_string())?;
    host.run(&model.command(project, &strings(&["config", "-q"])))?;
    let stamp = pc_host::fs::token_hex::<8>();
    let mut saved = Vec::new();
    let mut previous = Vec::new();
    let mut new_services = Vec::new();
    for service in &services {
        let container = host.query(&model.command(project, &strings(&["ps", "-a", "-q", service])))?;
        let container = container.trim();
        let image = if !container.is_empty() {
            if !super::digest(container) {
                return Err(format!("ambiguous {service} container"));
            }
            previous.push(service.clone());
            host.query(&strings(&["docker", "inspect", "--format", "{{.Image}}", container]))?
        } else {
            new_services.push(service.clone());
            host.query(&strings(&[
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                &format!("{project}-{service}:latest"),
            ]))
            .unwrap_or_default()
        };
        let image = image.trim();
        if !image.is_empty() {
            if !image.strip_prefix("sha256:").is_some_and(super::digest) {
                return Err(format!("invalid {service} image ID"));
            }
            host.run(&strings(&["docker", "tag", image, &format!("{project}-{service}:rollback-{stamp}")]))?;
            saved.push(service.clone());
        }
    }
    let mut up = strings(&["up", "-d", "--build", "--no-deps", "--wait"]);
    up.extend(services.clone());
    if let Err(error) = host.run(&model.command(project, &up)) {
        let rollback: Result<()> = (|| {
            for service in &saved {
                host.run(&strings(&[
                    "docker",
                    "tag",
                    &format!("{project}-{service}:rollback-{stamp}"),
                    &format!("{project}-{service}:latest"),
                ]))?;
            }
            if !new_services.is_empty() {
                let mut remove = strings(&["rm", "-s", "-f"]);
                remove.extend(new_services.clone());
                host.run(&model.command(project, &remove))?;
            }
            if !previous.is_empty() {
                let mut up = strings(&["up", "-d", "--no-build", "--no-deps", "--wait"]);
                up.extend(previous.clone());
                host.run(&model.command(project, &up))?;
            }
            Ok(())
        })();
        return match rollback {
            Ok(()) if new_services.is_empty() => Err(format!("the rebuild failed; previous images restored and verified: {error}")),
            Ok(()) => Err(format!("the rebuild failed; previous images restored, new services removed and require operator recovery: {error}")),
            Err(rollback) => Err(format!("manager rebuild failed: {error}; ROLLBACK FAILED: {rollback}")),
        };
    }
    drop(_lock);
    if !acked.is_empty() {
        // Old agents may not have the acknowledgement endpoint; the verified runtime is authoritative.
        let _ = host.agent("/v1/panel/managers/ack", Some(&json!({"names": acked})));
    }
    Ok(())
}

pub(super) fn update(host: &Host<'_>, version: &str, expected: &str) -> Result<String> {
    use std::os::unix::fs::FileTypeExt;
    if !std::fs::symlink_metadata(&host.socket).is_ok_and(|m| m.file_type().is_socket()) {
        return Err(format!(
            "version-agent not found ({}): see docs/UPGRADING.md, Installing the version-agent by hand",
            host.socket.display()
        ));
    }
    let initial = host.agent("/v1/versions", None)?;
    let current = panel(&initial)?.get("current").and_then(Value::as_str).unwrap_or("").to_string();
    let env = read_env(&host.env)?;
    let project =
        env.get("PROXY_CONTROL_COMPOSE_DIR").map(PathBuf::from).unwrap_or(host.path(pc_host::archive::PROJECT_DIR)?);
    let model = Model::new(&project, &env)?;
    let label = host.query(&strings(&[
        "docker",
        "inspect",
        "--format",
        "{{index .Config.Labels \"com.docker.compose.project\"}}",
        "proxy-control-panel",
    ]))?;
    let project_name = match label.trim() {
        OLD => OLD,
        NEW => NEW,
        _ => return Err("panel is not in the expected Compose project".into()),
    };
    scope(host, &model, project_name)?;
    // Mandatory boundary: a Python agent never receives a 4.0 update request.
    agent::migrate(host, version)?;
    agent::healthy(host, version)?;
    if current != version {
        let checked = host.agent("/v1/upstream/check", Some(&json!({})))?;
        let available = panel(&checked)?
            .get("available")
            .and_then(Value::as_array)
            .ok_or("the version-agent offers no panel release")?;
        let entry = available
            .iter()
            .find(|entry| entry.get("version").and_then(Value::as_str) == Some(version))
            .ok_or_else(|| format!("the version-agent does not offer {version}"))?;
        if entry.get("sha256").and_then(Value::as_str) != Some(expected) {
            return Err("the agent does not offer exactly this verified release".into());
        }
        // Re-read current after migration; another update is never silently overwritten.
        let fresh = host.agent("/v1/versions", None)?;
        let fresh_current = panel(&fresh)?.get("current").and_then(Value::as_str).unwrap_or("");
        if fresh_current != current {
            return Err("panel current version changed during preflight".into());
        }
        host.agent("/v1/update", Some(&json!({"component": "panel", "version": version, "expected_current": if current.is_empty() { Value::Null } else { json!(current) }})))?;
        let mut complete = false;
        for _ in 0..180 {
            host.sleep();
            let state = host.agent("/v1/versions", None)?;
            let state = panel(&state)?;
            if state.get("status").and_then(Value::as_str) == Some("updating") {
                continue;
            }
            if state.get("status").and_then(Value::as_str) == Some("ready")
                && state.get("current").and_then(Value::as_str) == Some(version)
            {
                complete = true;
                break;
            }
            return Err(format!(
                "the panel did not update: {}",
                state.get("last_error").and_then(Value::as_str).unwrap_or("unexpected panel status")
            ));
        }
        if !complete {
            return Err("the panel update timed out".into());
        }
    }
    // Agent restart health and pending reads are fatal, never silently interpreted as no work.
    let mut healthy = false;
    for _ in 0..30 {
        if agent::healthy(host, version).is_ok() {
            healthy = true;
            break;
        }
        host.sleep();
    }
    if !healthy {
        return Err("the Rust version-agent did not return healthy after the panel update".into());
    }
    if host.query(&strings(&["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"]))?.trim() != version {
        return Err(format!("the panel container does not report {version}"));
    }
    let mut settled = None;
    for _ in 0..360 {
        let state = host.agent("/v1/versions", None)?;
        let p = panel(&state)?;
        if p.get("rebuilding_managers").and_then(Value::as_bool) == Some(true) {
            host.sleep();
            continue;
        }
        settled = Some(pending(p)?);
        break;
    }
    let pending = settled.ok_or("the version-agent manager rebuild timed out")?;
    rebuild(host, &model, project_name, &pending)?;
    crate::ingress_upgrade::upgrade(&project, &host.root, true, host.runner).map_err(|e| e.to_string())?;
    let moved = super::compose::migrate(host, &project, false)?;
    // The Rust agent's handoff owns new sync entries; repair transitions host helper checkpoints.
    let store = crate::store::TransactionStore::new(&host.root).map_err(|e| e.to_string())?;
    if store.state_exists() {
        let context = crate::adapters::AdapterContext {
            root: host.root.clone(),
            tree: host.source.clone(),
            runner: std::sync::Arc::new(pc_host::runner::SystemRunner),
        };
        let services = crate::cli::Services::with_context(
            context,
            Box::new(|_| Ok(Default::default())),
            Box::new(crate::adapters::mcp_handoff),
        )
        .map_err(|e| e.message())?;
        services.engine.repair().map_err(|e| e.message())?;
    }
    let names = host.query(&strings(&[
        "docker",
        "ps",
        "-a",
        "--filter",
        &format!("label=com.docker.compose.project={NEW}"),
        "--format",
        "{{.Names}}",
    ]))?;
    let mut bad = BTreeSet::new();
    for name in names.lines().filter(|name| !name.is_empty()) {
        let health = host.query(&strings(&[
            "docker",
            "inspect",
            "-f",
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
            name,
        ]))?;
        if !matches!(health.trim(), "healthy" | "running") {
            bad.insert(format!("{name}={}", health.trim()));
        }
    }
    if !bad.is_empty() {
        return Err(format!("unhealthy: {}", bad.into_iter().collect::<Vec<_>>().join(" ")));
    }
    agent::healthy(host, version)?;
    Ok(format!("{moved}done: Proxy Control {version}\n"))
}
