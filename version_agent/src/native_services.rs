//! Fixed, root-only maintenance for the standard managed deployment. Executed by
//! the existing deferred systemd-run restart surface, outside the old unit's
//! read-only mount namespace. It never replaces an installer-owned base unit.
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::runner::{Command, CommandRunner};

pub const BINARY: &str = "/opt/proxy-control/version_agent/bin/linux-amd64/proxy-control-version-agent";
pub const FLAG: &str = "--refresh-native-services";
const UNIT: &str = "/etc/systemd/system/version-agent.service";
const DROPIN: &str = "/etc/systemd/system/version-agent.service.d/50-naive-live-meter.conf";
const CADDY_DIR: &str = "/etc/systemd/system/caddy-naive.service.d";
const CONTENT: &[u8] = b"[Service]\nReadWritePaths=/etc/systemd/system/caddy-naive.service.d\n";

fn checked_path(root: &Path, absolute: &str) -> Result<std::path::PathBuf, String> {
    let path = pc_host::fs::root_path(root, absolute).map_err(|e| e.to_string())?;
    let mut cursor = root.to_path_buf();
    for part in Path::new(absolute).components().skip(1) {
        cursor.push(part);
        if fs::symlink_metadata(&cursor).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("native service maintenance refuses symlinks".into());
        }
    }
    Ok(path)
}

pub fn refresh(root: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    let effective_uid = unsafe { libc::geteuid() };
    if root == Path::new("/") && effective_uid != 0 {
        return Err("native service maintenance requires root".into());
    }
    let file_owner = (effective_uid == 0).then_some((0, 0));
    let store = installer::TransactionStore::new(root).map_err(|e| e.to_string())?;
    let _lock = store.locked().map_err(|e| e.to_string())?;
    let unit = checked_path(root, UNIT)?;
    let meta = fs::symlink_metadata(&unit).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != effective_uid || meta.mode() & 0o022 != 0 {
        return Err("version-agent base unit is not root-managed".into());
    }
    let ownership = store.read_ownership().map_err(|e| e.to_string())?;
    let entry = ownership.get(UNIT).ok_or("version-agent base unit has no installer ownership")?;
    if entry.adapter != "version_agent"
        || entry.is_mutable()
        || entry.sha256 != pc_host::fs::sha256_file(&unit).map_err(|e| e.to_string())?
    {
        return Err("version-agent base unit ownership differs from the installer journal".into());
    }
    let text = fs::read_to_string(&unit).map_err(|e| e.to_string())?;
    let starts: Vec<_> = text.lines().filter_map(|line| line.strip_prefix("ExecStart=")).collect();
    if starts != [BINARY] || !text.lines().any(|line| line == "User=root") {
        return Err("version-agent base unit is not the standard native managed service".into());
    }
    let dropin = checked_path(root, DROPIN)?;
    let previous = match fs::read(&dropin) {
        Ok(bytes) if bytes == CONTENT => Some(bytes),
        Ok(_) => return Err("unexpected native service maintenance override; preserving it".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let caddy_dir = checked_path(root, CADDY_DIR)?;
    pc_host::fs::durable_mkdir(&caddy_dir, 0o755).map_err(|e| e.to_string())?;
    if fs::metadata(&caddy_dir).map_err(|e| e.to_string())?.uid() != effective_uid {
        return Err("Caddy service drop-in directory is not root-owned".into());
    }
    fs::set_permissions(&caddy_dir, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    pc_host::fs::durable_mkdir(dropin.parent().unwrap(), 0o755).map_err(|e| e.to_string())?;
    let parent_meta = fs::metadata(dropin.parent().unwrap()).map_err(|e| e.to_string())?;
    if parent_meta.uid() != effective_uid || parent_meta.mode() & 0o022 != 0 {
        return Err("version-agent service drop-in directory is not private to root".into());
    }
    pc_host::fs::atomic_write(&dropin, CONTENT, 0o644, file_owner).map_err(|e| e.to_string())?;
    let outcome = (|| {
        runner.run(&Command::new(&["systemctl", "daemon-reload"]))?;
        runner.run(&Command::new(&["systemctl", "restart", "version-agent"]))?;
        runner.run(&Command::new(&["systemctl", "is-active", "version-agent"]))?;
        Ok::<_, crate::runner::CommandError>(())
    })();
    if let Err(error) = outcome {
        match previous {
            Some(bytes) => pc_host::fs::atomic_write(&dropin, &bytes, 0o644, file_owner).map_err(|e| e.to_string())?,
            None => pc_host::fs::durable_remove(&dropin, false).map_err(|e| e.to_string())?,
        }
        let _ = runner.run(&Command::new(&["systemctl", "daemon-reload"]));
        let restored = runner.run(&Command::new(&["systemctl", "restart", "version-agent"]));
        return Err(format!("native service refresh failed: {error}; previous config restart: {restored:?}"));
    }
    Ok(())
}

/// Native-service migration is optional to the ordinary deferred self-update
/// restart. Refusal/busy must not leave the just-updated binary unloaded.
pub fn refresh_or_restart(root: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    if let Err(error) = refresh(root, runner) {
        log::warn!("native service migration refused; restarting without migration: {error}");
        let _ = claim_startup_attempt(root);
        runner.run(&Command::new(&["systemctl", "restart", "version-agent"])).map_err(|e| e.to_string())?;
        runner.run(&Command::new(&["systemctl", "is-active", "version-agent"])).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn claim_startup_attempt(root: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(path) = checked_path(root, "/var/lib/proxy-control/version-agent/native-services-refresh.attempted") else {
        return false;
    };
    if pc_host::fs::durable_mkdir(path.parent().unwrap(), 0o700).is_err() {
        return false;
    }
    // Persistent once-per-deployment guard: even an unexpected override or a
    // busy installer lock cannot turn the startup fallback into a restart loop.
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path).is_ok()
}

/// The first release containing this helper can be installed by an older worker
/// which schedules only `systemctl restart`. Bootstrap the same fixed maintenance
/// once on startup; custom binaries, test binaries and non-managed hosts do not.
pub fn schedule_legacy_refresh(runner: &dyn CommandRunner) {
    if std::env::current_exe().ok().as_deref() != Some(Path::new(BINARY))
        || fs::read(DROPIN).ok().as_deref() == Some(CONTENT)
        || !claim_startup_attempt(Path::new("/"))
    {
        return;
    }
    if let Err(error) = runner.run(&Command::new(&crate::updater::AGENT_RESTART)) {
        log::warn!("native service refresh could not be scheduled: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn managed(root: &Path) -> installer::TransactionStore {
        let unit = root.join(UNIT.trim_start_matches('/'));
        fs::create_dir_all(unit.parent().unwrap()).unwrap();
        fs::write(&unit, format!("[Service]\nUser=root\nExecStart={BINARY}\nProtectSystem=strict\n")).unwrap();
        let store = installer::TransactionStore::new(root).unwrap();
        store.initialize().unwrap();
        let entry = installer::journal::OwnershipEntry {
            action_id: "agent".into(),
            adapter: "version_agent".into(),
            kind: "file".into(),
            mutable: None,
            preserve: false,
            sha256: pc_host::fs::sha256_file(&unit).unwrap(),
        };
        store.write_ownership(&[(UNIT.to_string(), entry)].into_iter().collect()).unwrap();
        store
    }
    #[test]
    fn refresh_preserves_owned_unit_and_installs_only_narrow_override() {
        let dir = crate::testutil::TempDir::new("native-refresh");
        managed(dir.path());
        let before = fs::read(dir.join(UNIT.trim_start_matches('/'))).unwrap();
        let calls = std::sync::Mutex::new(Vec::new());
        refresh(dir.path(), &|c: &Command| {
            calls.lock().unwrap().push(c.argv.clone());
            Ok(String::new())
        })
        .unwrap();
        assert_eq!(fs::read(dir.join(UNIT.trim_start_matches('/'))).unwrap(), before);
        assert_eq!(fs::read(dir.join(DROPIN.trim_start_matches('/'))).unwrap(), CONTENT);
        assert_eq!(
            calls.into_inner().unwrap(),
            [
                vec!["systemctl", "daemon-reload"],
                vec!["systemctl", "restart", "version-agent"],
                vec!["systemctl", "is-active", "version-agent"]
            ]
        );
    }
    #[test]
    fn refresh_refuses_unmanaged_unit_and_unexpected_override() {
        for damage in ["unit", "override"] {
            let dir = crate::testutil::TempDir::new("native-refresh-refuse");
            managed(dir.path());
            if damage == "unit" {
                fs::write(dir.join(UNIT.trim_start_matches('/')), b"foreign").unwrap();
            } else {
                let path = dir.join(DROPIN.trim_start_matches('/'));
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"operator override").unwrap();
            }
            assert!(refresh(dir.path(), &|_: &Command| { panic!("must refuse before commands") }).is_err());
        }
    }
    #[test]
    fn refresh_failure_restores_previous_dropin_generation() {
        let dir = crate::testutil::TempDir::new("native-refresh-rollback");
        managed(dir.path());
        let fail_once = std::sync::atomic::AtomicBool::new(true);
        let result = refresh(dir.path(), &|c: &Command| {
            if c.argv == ["systemctl", "restart", "version-agent"]
                && fail_once.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(crate::runner::CommandError::Other("synthetic restart failure".into()));
            }
            Ok("active".into())
        });
        assert!(result.is_err());
        assert!(!dir.join(DROPIN.trim_start_matches('/')).exists());
    }

    #[test]
    fn refresh_busy_keeps_the_normal_deferred_restart_and_does_not_loop() {
        let dir = crate::testutil::TempDir::new("native-refresh-busy");
        let store = managed(dir.path());
        let _busy = store.locked().unwrap();
        let calls = std::sync::Mutex::new(Vec::new());
        refresh_or_restart(dir.path(), &|c: &Command| {
            calls.lock().unwrap().push(c.argv.clone());
            Ok("active".into())
        })
        .unwrap();
        assert_eq!(
            calls.into_inner().unwrap(),
            [vec!["systemctl", "restart", "version-agent"], vec!["systemctl", "is-active", "version-agent"]]
        );
        assert!(!dir.join(DROPIN.trim_start_matches('/')).exists());
        assert!(!claim_startup_attempt(dir.path()));
    }
    #[test]
    fn unexpected_override_does_not_suppress_self_update_restart() {
        let dir = crate::testutil::TempDir::new("native-refresh-foreign-restart");
        managed(dir.path());
        let path = dir.join(DROPIN.trim_start_matches('/'));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"operator override").unwrap();
        let calls = std::sync::Mutex::new(Vec::new());
        refresh_or_restart(dir.path(), &|c: &Command| {
            calls.lock().unwrap().push(c.argv.clone());
            Ok("active".into())
        })
        .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"operator override");
        assert_eq!(calls.into_inner().unwrap()[0], vec!["systemctl", "restart", "version-agent"]);
    }

    #[test]
    fn deferred_self_update_runs_fixed_native_service_maintenance() {
        assert_eq!(crate::updater::AGENT_RESTART[3], BINARY);
        assert_eq!(crate::updater::AGENT_RESTART[4], FLAG);
    }
}
