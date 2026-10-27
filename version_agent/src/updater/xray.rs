//! Xray (`_update_xray`): the router's pinned bin dir (`xray`, `geoip.dat`, `geosite.dat`), the
//! digests in `.env.xray-router`, a router recreate and its own report of the running version.

use std::fs;

use serde_json::{Map, Value};

use crate::catalog::CatalogEntry;
use crate::service::VersionAgent;

use super::{
    argv, atomic_write, chmod, compose_up, copyfile, is_symlink, read_if_exists, refuse, restore_copy, restore_file,
    rewrite_env_line, rolled_back, run, state_dir, unlink_missing_ok, HostUpdater, Step, MAX_ARTIFACT,
};

/// `XRAY_MODES` (also the order the members are written and their overlay keys set).
pub const XRAY_MODES: [(&str, u32); 3] = [("xray", 0o755), ("geoip.dat", 0o644), ("geosite.dat", 0o644)];
/// `XRAY_KEYS`: the overlay variable that pins each member by digest.
pub const XRAY_KEYS: [(&str, &str); 3] = [
    ("xray", "XRAY_ROUTER_XRAY_SHA256"),
    ("geoip.dat", "XRAY_ROUTER_GEOIP_SHA256"),
    ("geosite.dat", "XRAY_ROUTER_GEOSITE_SHA256"),
];
/// `XRAY_STATUS_COMMAND`: the manager's `/v1/status`, read over its own socket from inside the
/// container. 4.0: the manager is a Rust binary; a router still on an image from before its
/// rebuild (the manager's change pending, the Xray pin updated first) has the Python module.
pub const XRAY_STATUS_COMMAND: [&str; 3] = [
    "sh",
    "-c",
    "if [ -x /usr/local/bin/xray-router-manager ]; then exec /usr/local/bin/xray-router-manager healthcheck --status; \
     else exec python -m xray_router_manager.healthcheck --status; fi",
];

/// `_xray_status()`.
fn xray_status(agent: &VersionAgent) -> Step<Map<String, Value>> {
    let mut command = argv(&["docker", "exec", &agent.config.xray_container]);
    command.extend(argv(&XRAY_STATUS_COMMAND));
    let output = run(agent, &command, 30)?;
    let value = pc_host::json::loads(output.as_bytes()).map_err(|_| refuse("xray-router status is not JSON"))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(refuse("xray-router status is not an object")),
    }
}

/// `str(value or default)` of a status field.
fn field_text(status: &Map<String, Value>, key: &str, default: &str) -> String {
    let value = status.get(key).cloned().unwrap_or(Value::Null);
    if !pc_common::pyvalue::truthy(&value) {
        return default.to_string();
    }
    match value {
        Value::String(text) => text,
        other => crate::py::scalar_text(&other).unwrap_or_else(|| other.to_string()),
    }
}

/// `_assert_xray_running(expected)`: the router is idle and runs `Xray <expected> …`.
fn assert_xray_running(agent: &VersionAgent, expected: Option<&str>) -> Step<()> {
    let status = xray_status(agent)?;
    if status.get("phase").and_then(Value::as_str) != Some("idle") {
        return Err(refuse(format!("xray-router is not idle: {}", field_text(&status, "phase", "unknown"))));
    }
    let reported = field_text(&status, "xray_version", "");
    let words = pc_common::pytext::split(&reported);
    let running = if words.len() >= 2 && words[0] == "Xray" { words[1] } else { "" };
    if let Some(expected) = expected {
        if running != expected {
            let shown = if running.is_empty() { "unknown" } else { running };
            return Err(refuse(format!("xray-router runs {shown}, expected {expected}")));
        }
    }
    Ok(())
}

/// `_update_xray(entry, previous_version)`: returns the members' digests.
pub fn update_xray(
    updater: &HostUpdater,
    agent: &VersionAgent,
    entry: &CatalogEntry,
    previous_version: Option<&str>,
) -> Step<Map<String, Value>> {
    let archive = entry.archive.clone().unwrap_or_default();
    let members = archive.get("members").and_then(Value::as_object).cloned().unwrap_or_default();
    let names_match =
        members.len() == XRAY_MODES.len() && XRAY_MODES.iter().all(|(name, _)| members.contains_key(*name));
    let present = |value: &Option<String>| value.as_deref().is_some_and(|v| !v.is_empty());
    if entry.kind != "binary" || !present(&entry.url) || !present(&entry.sha256) || archive.is_empty() || !names_match {
        return Err(refuse("xray entry must name the archive members"));
    }
    let bin_dir = agent.config.xray_bin_dir.clone();
    if is_symlink(&bin_dir) || !bin_dir.is_dir() {
        return Err(refuse("xray-router binary directory is missing"));
    }
    let payload = updater.download(entry.url.as_deref().unwrap_or_default(), MAX_ARTIFACT)?;
    if Some(pc_host::fs::sha256_hex(&payload)) != entry.sha256 {
        return Err(refuse("xray artifact SHA-256 mismatch"));
    }
    let format = archive.get("format").and_then(Value::as_str);
    let mut extracted: Vec<(&str, u32, Vec<u8>)> = Vec::new();
    for (name, mode) in XRAY_MODES {
        let path = members.get(name).and_then(Value::as_str).unwrap_or_default();
        let data = crate::artifacts::extract_member(&payload, format, path, crate::artifacts::MAX_MEMBER)
            .map_err(|err| refuse(format!("xray archive: {err}")))?;
        extracted.push((name, mode, data));
    }
    let digests: Map<String, Value> = extracted
        .iter()
        .map(|(name, _, data)| (name.to_string(), Value::String(pc_host::fs::sha256_hex(data))))
        .collect();
    let backup_dir = state_dir(agent).join("backups").join("xray.previous");
    fs::create_dir_all(&backup_dir)?;
    let mut existed = Vec::new();
    for (name, mode, _) in &extracted {
        let path = bin_dir.join(name);
        if is_symlink(&path) {
            return Err(refuse(format!("refusing to replace symlink {}", path.display())));
        }
        let exists = path.exists();
        if exists {
            copyfile(&path, &backup_dir.join(name))?;
            chmod(&backup_dir.join(name), *mode)?;
        }
        existed.push(exists);
    }
    let overlay = agent.config.xray_overlay.clone();
    let previous_overlay = read_if_exists(&overlay)?;
    let outcome = (|| -> Step<()> {
        for (name, mode, data) in &extracted {
            atomic_write(&bin_dir.join(name), data, *mode)?;
        }
        pc_host::fs::fsync_directory(&bin_dir)?;
        for (name, key) in XRAY_KEYS {
            let digest = digests.get(name).and_then(Value::as_str).unwrap_or_default();
            rewrite_env_line(&overlay, key, digest)?;
        }
        compose_up(agent, "xray-router")?;
        assert_xray_running(agent, Some(&entry.version))
    })();
    if let Err(exc) = outcome {
        let rollback = (|| -> Step<()> {
            for ((name, mode, _), exists) in extracted.iter().zip(&existed) {
                if *exists {
                    restore_copy(&backup_dir.join(name), &bin_dir.join(name), *mode)?;
                } else {
                    unlink_missing_ok(&bin_dir.join(name))?;
                }
            }
            pc_host::fs::fsync_directory(&bin_dir)?;
            restore_file(&overlay, previous_overlay.as_deref(), 0o600)?;
            compose_up(agent, "xray-router")?;
            assert_xray_running(agent, previous_version)
        })();
        return Err(rolled_back(
            exc,
            rollback,
            "xray update failed; restored generation could not be verified".into(),
            "xray update failed; previous generation was restored and verified".into(),
        ));
    }
    Ok(digests)
}
