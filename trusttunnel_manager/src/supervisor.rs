//! Runs the pinned trusttunnel_endpoint binary as a child process.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STOP_TIMEOUT: Duration = Duration::from_secs(10);

pub trait Supervisor: Send {
    fn start(&mut self, vpn_toml: &Path, hosts_toml: &Path) -> io::Result<()>;
    fn stop(&mut self);
    fn running(&mut self) -> bool;
    /// SIGHUP: the endpoint re-reads hosts.toml and its certificates without dropping sessions.
    fn reload(&mut self) -> io::Result<()>;
    fn pid(&mut self) -> Option<u32>;
}

pub struct ProcessSupervisor {
    binary: PathBuf,
    child: Option<Child>,
}

impl ProcessSupervisor {
    pub fn new(binary: PathBuf) -> Self {
        Self { binary, child: None }
    }
}

fn signal(child: &Child, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: kill(2) on our own child's pid; the child is not reaped while we hold it.
    if unsafe { libc::kill(child.id() as libc::pid_t, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn wait_for(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) if Instant::now() >= deadline => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

impl Supervisor for ProcessSupervisor {
    fn start(&mut self, vpn_toml: &Path, hosts_toml: &Path) -> io::Result<()> {
        self.stop();
        // The endpoint reads its settings at start only; relative paths inside them are avoided
        // by the manager, so the working directory does not matter.
        let child = Command::new(&self.binary)
            .arg(vpn_toml)
            .arg(hosts_toml)
            .stdin(Stdio::null())
            .current_dir(vpn_toml.parent().unwrap_or(Path::new("/")))
            .spawn()?;
        self.child = Some(child);
        Ok(())
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        let _ = signal(&child, libc::SIGTERM);
        if !wait_for(&mut child, STOP_TIMEOUT) {
            log::warn!("endpoint ignored SIGTERM, killing it");
            let _ = child.kill();
            wait_for(&mut child, STOP_TIMEOUT);
        }
    }

    fn reload(&mut self) -> io::Result<()> {
        if !self.running() {
            return Err(io::Error::other("endpoint is not running"));
        }
        signal(self.child.as_ref().expect("running implies a child"), libc::SIGHUP)
    }

    fn running(&mut self) -> bool {
        self.child.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }

    fn pid(&mut self) -> Option<u32> {
        if self.running() {
            self.child.as_ref().map(Child::id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_reloads_and_stops_a_real_process() {
        let dir = std::env::temp_dir().join(format!("tt-sup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("endpoint.sh");
        std::fs::write(&script, "#!/bin/sh\ntrap 'echo hup >> hups' HUP\n: > ready\nwhile :; do sleep 0.05; done\n")
            .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut sup = ProcessSupervisor::new(script);
        assert!(sup.reload().is_err());
        sup.start(&dir.join("vpn.toml"), &dir.join("hosts.toml")).unwrap();
        assert!(sup.running() && sup.pid().is_some());
        let wait_for_file = |name: &str| {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !dir.join(name).exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
        };
        wait_for_file("ready");
        sup.reload().unwrap();
        wait_for_file("hups");
        assert!(std::fs::read_to_string(dir.join("hups")).unwrap().contains("hup"));
        sup.stop();
        assert!(!sup.running() && sup.pid().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
