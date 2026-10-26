use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use serde_json::Value;

use super::{read_env, safe_name, strings, Host, Result};

pub(super) const OLD: &str = "mtproxy";
pub(super) const NEW: &str = "proxy_panel_by_dubr1k";

pub(super) struct Model {
    pub files: Vec<String>,
    pub args: Vec<String>,
}

impl Model {
    pub fn new(project: &Path, env: &BTreeMap<String, String>) -> Result<Self> {
        let mut args = strings(&[
            "--project-directory",
            &project.to_string_lossy(),
            "--env-file",
            &project.join(".env").to_string_lossy(),
        ]);
        for name in [
            ".optional.env",
            ".env.naive",
            ".env.mieru",
            ".env.xray-router",
            ".env.amneziawg",
            ".env.trusttunnel",
            ".env.mcp",
        ] {
            let path = project.join(name);
            if path.is_file() {
                args.extend(strings(&["--env-file", &path.to_string_lossy()]));
            }
        }
        let files: Vec<String> = env
            .get("PROXY_CONTROL_COMPOSE_FILES")
            .map_or("compose.yaml", String::as_str)
            .split(':')
            .map(str::to_string)
            .collect();
        for file in &files {
            if !safe_name(file) || !project.join(file).is_file() {
                return Err(format!("no Compose file {file}"));
            }
            args.extend(strings(&["-f", &project.join(file).to_string_lossy()]));
        }
        let overrides = project.join("version-overrides/compose.versions.yaml");
        if overrides.is_file() {
            args.extend(strings(&["-f", &overrides.to_string_lossy()]));
        }
        Ok(Model { files, args })
    }
    pub fn command(&self, project: &str, tail: &[String]) -> Vec<String> {
        let mut args = strings(&["docker", "compose", "--project-name", project]);
        args.extend(self.args.iter().cloned());
        args.extend(tail.iter().cloned());
        args
    }
    pub fn has(&self, file: &str) -> bool {
        self.files.iter().any(|f| f == file)
    }
}

fn lines(text: &str) -> Vec<String> {
    text.lines().filter(|s| !s.is_empty()).map(str::to_string).collect()
}

fn preflight(model: &Value, running: &[String]) -> Result<()> {
    let services = model.get("services").and_then(Value::as_object).ok_or("the Compose model has no services")?;
    let missing: Vec<&str> = running.iter().filter(|name| !services.contains_key(*name)).map(String::as_str).collect();
    if !missing.is_empty() {
        return Err(format!("not in the model: {}", missing.join(" ")));
    }
    let mut start = BTreeSet::new();
    let mut queue = running.to_vec();
    let mut absent = BTreeSet::new();
    while let Some(name) = queue.pop() {
        if !start.insert(name.clone()) {
            continue;
        }
        let Some(service) = services.get(&name) else { continue };
        if let Some(deps) = service.get("depends_on").and_then(Value::as_object) {
            queue.extend(deps.keys().cloned());
        }
        if let Some(volumes) = service.get("volumes").and_then(Value::as_array) {
            for volume in volumes {
                if volume.get("type").and_then(Value::as_str) == Some("bind")
                    && volume.pointer("/bind/create_host_path").and_then(Value::as_bool) != Some(true)
                {
                    if let Some(path) = volume.get("source").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                        if !Path::new(path).exists() {
                            absent.insert(path.to_string());
                        }
                    }
                }
            }
        }
        if let Some(secrets) = service.get("secrets").and_then(Value::as_array) {
            for secret in secrets {
                if let Some(name) = secret.get("source").and_then(Value::as_str) {
                    if let Some(path) = model
                        .get("secrets")
                        .and_then(|s| s.get(name))
                        .and_then(|s| s.get("file"))
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        if !Path::new(path).exists() {
                            absent.insert(path.to_string());
                        }
                    }
                }
            }
        }
    }
    if absent.is_empty() {
        Ok(())
    } else {
        Err(format!("missing host paths: {}", absent.into_iter().collect::<Vec<_>>().join(" ")))
    }
}

pub(super) fn migrate(host: &Host<'_>, project: &Path, check: bool) -> Result<String> {
    let _lock = pc_host::operation_lock(&host.root).map_err(|e| e.to_string())?;
    let old_containers = lines(&host.query(&strings(&[
        "docker",
        "ps",
        "-a",
        "-q",
        "--filter",
        &format!("label=com.docker.compose.project={OLD}"),
    ]))?);
    if old_containers.is_empty() {
        return Ok(format!("the stack already runs as {NEW}\n"));
    }
    let env = read_env(&host.env)?;
    let model = Model::new(project, &env)?;
    let config: Value =
        serde_json::from_str(&host.query(&model.command(NEW, &strings(&["config", "--format", "json"])))?)
            .map_err(|e| e.to_string())?;
    let running: Vec<String> = lines(&host.query(&strings(&[
        "docker",
        "ps",
        "--filter",
        &format!("label=com.docker.compose.project={OLD}"),
        "--format",
        "{{.Label \"com.docker.compose.service\"}}",
    ]))?)
    .into_iter()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    if running.is_empty() {
        return Err(format!("nothing runs in the {OLD} project"));
    }
    if running.iter().any(|name| !safe_name(name)) {
        return Err("unsafe Compose service name".into());
    }
    preflight(&config, &running).map_err(|e| format!("the model cannot move this stack, nothing was stopped: {e}"))?;
    let services = config["services"].as_object().ok_or("missing Compose services")?;
    let built: Vec<&String> =
        running.iter().filter(|name| services.get(*name).is_some_and(|v| v.get("build").is_some())).collect();
    let data: Vec<String> = config
        .get("volumes")
        .and_then(Value::as_object)
        .map(|volumes| {
            volumes
                .iter()
                .filter(|(_, v)| {
                    v.get("external").and_then(Value::as_bool) != Some(true)
                        && v.pointer("/driver_opts/type").and_then(Value::as_str) != Some("tmpfs")
                })
                .map(|(key, _)| key.clone())
                .collect()
        })
        .unwrap_or_default();
    if data.iter().any(|name| !safe_name(name)) {
        return Err("unsafe Compose volume name".into());
    }
    if check {
        return Ok(format!(
            "check passed: {OLD} → {NEW}, services {}, volumes {}\n",
            running.join(" "),
            data.join(" ")
        ));
    }
    // Validate every destination volume before stopping or creating anything. Never delete a foreign volume during rollback.
    for volume in &data {
        if host.query(&strings(&["docker", "volume", "inspect", &format!("{NEW}_{volume}")])).is_ok() {
            return Err(format!("volume {NEW}_{volume} already exists — inspect it by hand"));
        }
    }
    for service in built {
        let container = host.query(&model.command(OLD, &strings(&["ps", "-q", service])))?;
        let image = host.query(&strings(&["docker", "inspect", "--format", "{{.Image}}", container.trim()]))?;
        let image = image.trim();
        if !image.strip_prefix("sha256:").is_some_and(super::digest) {
            return Err(format!("invalid {service} image ID"));
        }
        host.run(&strings(&["docker", "tag", image, &format!("{NEW}-{service}:latest")]))?;
    }
    let previous_env = if host.env.is_file() {
        Some((fs::read(&host.env).map_err(|e| e.to_string())?, fs::metadata(&host.env).map_err(|e| e.to_string())?))
    } else {
        None
    };
    let mut copied = Vec::new();
    let result: Result<()> = (|| {
        host.run(&model.command(OLD, &strings(&["stop"])))?;
        let compose_version = host.query(&strings(&["docker", "compose", "version", "--short"]))?;
        for volume in &data {
            let old = format!("{OLD}_{volume}");
            let new = format!("{NEW}_{volume}");
            if host.query(&strings(&["docker", "volume", "inspect", &old])).is_err() {
                continue;
            }
            host.run(&strings(&[
                "docker",
                "volume",
                "create",
                "--label",
                &format!("com.docker.compose.project={NEW}"),
                "--label",
                &format!("com.docker.compose.volume={volume}"),
                "--label",
                &format!("com.docker.compose.version={}", compose_version.trim()),
                &new,
            ]))?;
            copied.push(new.clone());
            let helper = host
                .query(&strings(&["docker", "image", "inspect", "--format", "{{.Id}}", &format!("{NEW}-panel:latest")]))
                .or_else(|_| {
                    host.query(&strings(&["docker", "inspect", "--format", "{{.Image}}", &old_containers[0]]))
                })?;
            host.run(&strings(&[
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0",
                "--entrypoint",
                "sh",
                "-v",
                &format!("{old}:/from:ro"),
                "-v",
                &format!("{new}:/to"),
                helper.trim(),
                "-c",
                "cp -a /from/. /to/",
            ]))?;
        }
        host.run(&model.command(OLD, &strings(&["down", "--remove-orphans"])))?;
        let mut up = strings(&["up", "-d", "--no-build", "--wait"]);
        up.extend(running.clone());
        host.run(&model.command(NEW, &up))?;
        if let Some((bytes, meta)) = &previous_env {
            let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
            let changed = text
                .lines()
                .map(|line| match line {
                    "PROXY_CONTROL_PANEL_IMAGE=mtproxy-panel" => {
                        "PROXY_CONTROL_PANEL_IMAGE=proxy_panel_by_dubr1k-panel"
                    }
                    "PROXY_CONTROL_PANEL_VOLUME=mtproxy_panel-data" => {
                        "PROXY_CONTROL_PANEL_VOLUME=proxy_panel_by_dubr1k_panel-data"
                    }
                    _ => line,
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            pc_host::fs::atomic_write(
                &host.env,
                changed.as_bytes(),
                meta.permissions().mode() & 0o777,
                Some((meta.uid(), meta.gid())),
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let rollback = (|| {
            host.run(&model.command(NEW, &strings(&["down", "--remove-orphans"])))?;
            for volume in &copied {
                host.run(&strings(&["docker", "volume", "rm", volume]))?;
            }
            if let Some((bytes, meta)) = &previous_env {
                pc_host::fs::atomic_write(
                    &host.env,
                    bytes,
                    meta.permissions().mode() & 0o777,
                    Some((meta.uid(), meta.gid())),
                )
                .map_err(|e| e.to_string())?;
            }
            let mut up = strings(&["up", "-d", "--no-build", "--wait"]);
            up.extend(running.clone());
            host.run(&model.command(OLD, &up))
        })();
        return match rollback {
            Ok(()) => Err(format!("the stack did not come up as {NEW}; the {OLD} project is back: {error}")),
            Err(rollback) => Err(format!(
                "Compose migration failed: {error}; ROLLBACK FAILED: {rollback}; {OLD}_* volumes are untouched"
            )),
        };
    }
    // Only tmpfs socket volumes are disposable; retain every previous data volume for the operator.
    for volume in lines(&host.query(&strings(&[
        "docker",
        "volume",
        "ls",
        "-q",
        "--filter",
        &format!("label=com.docker.compose.project={OLD}"),
    ]))?) {
        if host
            .query(&strings(&["docker", "volume", "inspect", "--format", "{{index .Options \"type\"}}", &volume]))
            .is_ok_and(|s| s.trim() == "tmpfs")
        {
            let _ = host.run(&strings(&["docker", "volume", "rm", &volume]));
        }
    }
    Ok(format!("the stack runs as {NEW}. Previous {OLD}_* data volumes are retained for rollback.\n"))
}
