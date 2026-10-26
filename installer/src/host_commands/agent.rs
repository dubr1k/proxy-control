use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use pc_host::archive::{verify_binaries, ReleaseIdentity};
use pc_host::fs::{atomic_write, durable_mkdir, durable_remove, fsync_directory, fsync_tree, token_hex};
use serde_json::json;

use super::{strings, Host, Result};
use crate::migration::{AgentMigration, AGENT_UNIT};
use crate::store::TransactionStore;

const CODE: &str = "/opt/proxy-control/version_agent";
const TMPFILES: &str = "/etc/tmpfiles.d/proxy-control-version-agent.conf";
const BACKUPS: &str = "/var/lib/proxy-control/agent-migration";
const BINARY: &str = "/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent";

pub(super) fn healthy(host: &Host<'_>, version: &str) -> Result<()> {
    let health = host.agent("/v1/health", None)?;
    if health.get("status").and_then(|v| v.as_str()) != Some("ok")
        || health.get("implementation").and_then(|v| v.as_str()) != Some("rust")
        || health.get("version").and_then(|v| v.as_str()) != Some(version)
    {
        return Err(format!("version-agent health does not prove Rust release {version}"));
    }
    Ok(())
}

fn wait(host: &Host<'_>, version: Option<&str>) -> Result<()> {
    let mut last = "version-agent did not become healthy".to_string();
    for _ in 0..30 {
        let result = if let Some(version) = version {
            healthy(host, version)
        } else {
            host.agent("/v1/health", None).and_then(|health| {
                if health.get("status").and_then(|v| v.as_str()) == Some("ok") {
                    Ok(())
                } else {
                    Err("restored version-agent is unhealthy".into())
                }
            })
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) => last = error,
        }
        host.sleep();
    }
    Err(last)
}

/// Copy only regular files/directories; never follow a release or installed symlink.
/// Bytecode from Python 3.x is not executable source and is not carried into a new tree.
pub(super) fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(source).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(format!("unsafe code directory: {}", source.display()));
    }
    durable_mkdir(target, meta.permissions().mode() & 0o777).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name() == "__pycache__" || entry.path().extension().is_some_and(|ext| ext == "pyc") {
            continue;
        }
        let metadata = entry.file_type().map_err(|e| e.to_string())?;
        if metadata.is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        } else if metadata.is_file() {
            pc_host::fs::durable_copy2(&entry.path(), &target.join(entry.file_name())).map_err(|e| e.to_string())?;
        } else {
            return Err(format!("unsafe code member: {}", entry.path().display()));
        }
    }
    fsync_tree(target).map_err(|e| e.to_string())
}

fn snapshot(source: &Path, backup: &Path) -> Result<()> {
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
        Ok(meta) if meta.file_type().is_file() => pc_host::fs::durable_copy2(source, backup).map_err(|e| e.to_string()),
        Ok(_) => Err(format!("unsafe migration file: {}", source.display())),
    }
}

fn restore_file(backup: &Path, target: &Path) -> Result<()> {
    if backup.exists() {
        pc_host::fs::durable_copy2(backup, target).map_err(|e| e.to_string())
    } else {
        durable_remove(target, true).map_err(|e| e.to_string())
    }
}

fn rewrite_unit(text: &str) -> Result<String> {
    let mut found = 0;
    let mut output = String::new();
    for line in text.lines() {
        if let Some(command) = line.strip_prefix("ExecStart=") {
            found += 1;
            if command != "/usr/bin/python3 -m version_agent.server" && command != BINARY {
                return Err("version-agent ExecStart is operator-customized; refusing to overwrite it".into());
            }
            output.push_str(&format!("ExecStart={BINARY}\n"));
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if found != 1 {
        return Err("version-agent unit must contain exactly one recognized ExecStart".into());
    }
    Ok(output)
}

fn restore(host: &Host<'_>, backup: &Path, store: &TransactionStore) -> Result<()> {
    host.run(&strings(&["systemctl", "stop", "version-agent"]))?;
    let code = host.path(CODE)?;
    let previous = backup.join("code");
    if !previous.is_dir() {
        return Err("agent rollback code snapshot is missing".into());
    }
    let staged = code.with_file_name(format!(".version-agent-restore-{}", token_hex::<8>()));
    copy_tree(&previous, &staged)?;
    durable_remove(&code, true).map_err(|e| e.to_string())?;
    fs::rename(&staged, &code).map_err(|e| e.to_string())?;
    fsync_directory(code.parent().ok_or("agent code parent is missing")?).map_err(|e| e.to_string())?;
    restore_file(&backup.join("unit"), &host.path(AGENT_UNIT)?)?;
    restore_file(&backup.join("tmpfiles"), &host.path(TMPFILES)?)?;
    if backup.join("journal-present").exists() {
        // State first, then its derived ownership journal, matching AgentMigration's protocol.
        restore_file(&backup.join("state.json"), store.state_path())?;
        restore_file(&backup.join("ownership.json"), store.ownership_path())?;
    }
    host.run(&strings(&["systemctl", "daemon-reload"]))?;
    host.run(&strings(&["systemctl", "start", "version-agent"]))?;
    wait(host, None)
}

pub(super) fn migrate(host: &Host<'_>, version: &str) -> Result<()> {
    let store = TransactionStore::new(&host.root).map_err(|e| e.to_string())?;
    let _lock = store.locked().map_err(|e| e.to_string())?;
    let backup_root = host.path(BACKUPS)?;
    let pending = backup_root.join("pending.json");
    if pending.exists() {
        let data: serde_json::Value =
            serde_json::from_slice(&fs::read(&pending).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let name = data
            .get("backup")
            .and_then(|v| v.as_str())
            .filter(|name| super::safe_name(name))
            .ok_or("invalid pending agent migration")?;
        restore(host, &backup_root.join(name), &store)
            .map_err(|e| format!("interrupted agent migration rollback failed: {e}"))?;
        durable_remove(&pending, false).map_err(|e| e.to_string())?;
    }
    let unit = host.path(AGENT_UNIT)?;
    let meta = fs::symlink_metadata(&unit).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("version-agent unit is not a regular file".into());
    }
    let installed_unit = fs::read_to_string(&unit).map_err(|e| e.to_string())?;
    let unit_text = rewrite_unit(&installed_unit)?;
    let native_unit = installed_unit.lines().any(|line| line.strip_prefix("ExecStart=") == Some(BINARY));
    if native_unit && healthy(host, version).is_ok() {
        return Ok(());
    }
    // A verified release identity is required even for no-journal hosts.
    let identity = ReleaseIdentity::read(&host.source).map_err(|e| e.to_string())?;
    if identity.version.as_deref() != Some(version)
        || identity.tag != format!("v{version}")
        || !identity.binaries.contains_key(pc_host::archive::identity::AGENT_BINARY)
        || fs::read_to_string(host.source.join("VERSION")).map_err(|e| e.to_string())?.trim() != version
    {
        return Err("agent migration source does not describe the requested release".into());
    }
    verify_binaries(&host.source, &identity)?;
    let code = host.path(CODE)?;
    let mut migration = AgentMigration::new(&store, &host.source);
    migration.prepare().map_err(|e| e.message())?;
    durable_mkdir(&backup_root, 0o700).map_err(|e| e.to_string())?;
    let name = format!("backup-{}", token_hex::<16>());
    let backup = backup_root.join(&name);
    durable_mkdir(&backup, 0o700).map_err(|e| e.to_string())?;
    // Stage source before stopping anything. A malformed tree never interrupts the agent.
    let staged = code.with_file_name(format!(".version-agent-next-{}", token_hex::<8>()));
    copy_tree(&host.source.join("version_agent"), &staged)?;
    let outcome: Result<()> = (|| {
        host.run(&strings(&["systemctl", "stop", "version-agent"]))?;
        copy_tree(&code, &backup.join("code"))?;
        snapshot(&unit, &backup.join("unit"))?;
        snapshot(&host.path(TMPFILES)?, &backup.join("tmpfiles"))?;
        if store.state_exists() {
            snapshot(store.state_path(), &backup.join("state.json"))?;
            snapshot(store.ownership_path(), &backup.join("ownership.json"))?;
            atomic_write(&backup.join("journal-present"), b"1\n", 0o600, Some((0, 0))).map_err(|e| e.to_string())?;
        }
        atomic_write(&pending, pc_host::json::pretty2(&json!({"backup": name})).as_bytes(), 0o600, Some((0, 0)))
            .map_err(|e| e.to_string())?;
        durable_remove(&code, false).map_err(|e| e.to_string())?;
        fs::rename(&staged, &code).map_err(|e| e.to_string())?;
        fsync_directory(code.parent().ok_or("agent code parent is missing")?).map_err(|e| e.to_string())?;
        atomic_write(&unit, unit_text.as_bytes(), meta.permissions().mode() & 0o777, Some((meta.uid(), meta.gid())))
            .map_err(|e| e.to_string())?;
        host.run(&strings(&["systemctl", "daemon-reload"]))?;
        host.run(&strings(&["systemctl", "start", "version-agent"]))?;
        wait(host, Some(version))?;
        migration.commit().map_err(|e| e.message())?;
        durable_remove(&pending, false).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(error) = outcome {
        let rollback = if pending.exists() {
            restore(host, &backup, &store)
        } else {
            host.run(&strings(&["systemctl", "start", "version-agent"])).and_then(|_| wait(host, None))
        };
        let _ = durable_remove(&staged, true);
        match rollback {
            Ok(()) => {
                durable_remove(&pending, true).map_err(|e| e.to_string())?;
                Err(format!("agent migration failed; previous generation restored and verified: {error}"))
            }
            Err(rollback) => Err(format!(
                "agent migration failed: {error}; ROLLBACK FAILED: {rollback}; backup: {}",
                backup.display()
            )),
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_unit_directives_and_refuses_custom_execstart() {
        let old = "[Service]\nEnvironmentFile=/custom.env\nExecStart=/usr/bin/python3 -m version_agent.server\nMemoryDenyWriteExecute=false\n";
        let new = rewrite_unit(old).unwrap();
        assert!(new.contains("EnvironmentFile=/custom.env\n"));
        assert!(new.contains("MemoryDenyWriteExecute=false\n"));
        assert!(new.contains(&format!("ExecStart={BINARY}\n")));
        assert!(rewrite_unit("ExecStart=/operator/bin/agent\n").is_err());
        assert!(rewrite_unit("ExecStart=/usr/bin/python3 -m version_agent.server\nExecStart=\n").is_err());
    }
}
