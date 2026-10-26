//! The update side of `tests/test_version_agent.py`, `tests/test_version_agent_managers.py`,
//! `tests/test_version_agent_protocol_managers.py`, `tests/test_version_agent_panel.py` and
//! `tests/test_version_agent_update_safety.py`, plus the golden replay of
//! `tests/fixtures/host-golden/agent/updates/02–05`.

use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::runner::{Command, CommandError, CommandRunner};
use crate::service::{AgentConfig, VersionAgent};
use crate::upstream::DownloadError;

use super::HostUpdater;

mod components;
mod golden;
mod journal;
mod panel;

type Answer = dyn Fn(&Command) -> Result<String, CommandError> + Send + Sync;

/// A runner that records every command (argv, environment, directory, timeout) and answers
/// through a closure — the `run(command, *, env, cwd, timeout)` fakes of the Python tests.
#[derive(Clone)]
pub(crate) struct Host {
    log: Arc<Mutex<Vec<Command>>>,
    answer: Arc<Answer>,
}

impl Host {
    pub fn new(answer: impl Fn(&Command) -> Result<String, CommandError> + Send + Sync + 'static) -> Host {
        Host { log: Arc::new(Mutex::new(Vec::new())), answer: Arc::new(answer) }
    }

    /// A host that answers every command with `text`.
    pub fn answering(text: &'static str) -> Host {
        Host::new(move |_| Ok(text.to_string()))
    }

    pub fn commands(&self) -> Vec<Command> {
        self.log.lock().unwrap().clone()
    }

    pub fn argvs(&self) -> Vec<Vec<String>> {
        self.commands().into_iter().map(|c| c.argv).collect()
    }
}

impl CommandRunner for Host {
    fn run(&self, command: &Command) -> Result<String, CommandError> {
        self.log.lock().unwrap().push(command.clone());
        (self.answer)(command)
    }
}

/// `RuntimeError(message)` raised by a fake runner.
pub(crate) fn runtime_error(message: &str) -> CommandError {
    CommandError::Other(message.to_string())
}

/// `argv == [...]`.
pub(crate) fn is(argv: &[String], expected: &[&str]) -> bool {
    argv.len() == expected.len() && argv.iter().zip(expected).all(|(a, b)| a == b)
}

/// `argv[:n] == [...]`.
pub(crate) fn starts(argv: &[String], prefix: &[&str]) -> bool {
    argv.len() >= prefix.len() && argv.iter().zip(prefix).all(|(a, b)| a == b)
}

pub(crate) fn has(argv: &[String], word: &str) -> bool {
    argv.iter().any(|part| part == word)
}

/// An updater whose downloads answer `payload` (and record nothing else).
pub(crate) fn serving(payload: Vec<u8>) -> HostUpdater {
    let mut updater = HostUpdater::with_downloader(move |_, _| Ok(payload.clone()));
    updater.sleep = Arc::new(|_| {});
    updater.machine = "x86_64".into();
    updater.system = "linux".into();
    updater
}

/// An updater that must not download.
pub(crate) fn no_download() -> HostUpdater {
    let mut updater =
        HostUpdater::with_downloader(|url, _| Err(DownloadError::Refused(format!("no download expected: {url}"))));
    updater.sleep = Arc::new(|_| {});
    updater.machine = "x86_64".into();
    updater.system = "linux".into();
    updater
}

/// A `VersionAgent` over `config`, answering commands through `host`, updating with `updater`.
pub(crate) fn agent_with(config: AgentConfig, host: &Host, updater: HostUpdater) -> Arc<VersionAgent> {
    let mut agent = VersionAgent::new(config);
    agent.runner = Arc::new(host.clone());
    agent.updater = Arc::new(updater);
    Arc::new(agent)
}

/// The agent's updater, to join its workers (`agent.panel_thread.join()`).
pub(crate) fn join(updater: &HostUpdater) {
    updater.join_workers();
}

pub(crate) fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

pub(crate) fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

pub(crate) fn text(path: &Path) -> String {
    String::from_utf8(read(path)).unwrap()
}

pub(crate) fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

pub(crate) fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub(crate) fn sha(data: &[u8]) -> String {
    pc_host::fs::sha256_hex(data)
}

pub(crate) fn state_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&read(path)).unwrap()
}

pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The `--env-file` values of a Compose argv.
pub(crate) fn env_files_of(argv: &[String]) -> Vec<String> {
    argv.windows(2).filter(|pair| pair[0] == "--env-file").map(|pair| pair[1].clone()).collect()
}

/// The `-f` values of a Compose argv.
pub(crate) fn files_of(argv: &[String]) -> Vec<String> {
    argv.windows(2).filter(|pair| pair[0] == "-f").map(|pair| pair[1].clone()).collect()
}

pub(crate) fn tail(argv: &[String], n: usize) -> Vec<&str> {
    argv[argv.len().saturating_sub(n)..].iter().map(String::as_str).collect()
}
