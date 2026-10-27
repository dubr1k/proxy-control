//! The narrow, argv-only boundary to the `mita` CLI. A config travels through an anonymous
//! file passed as `/proc/self/fd/<n>`, never on argv; output is bounded; the CLI runs in its
//! own session and the whole process group is killed when it returns or times out.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::{pyjson, util};

pub const DEFAULT_MAX_OUTPUT: usize = 1_048_576;
pub const STATUSES: [&str; 6] = ["RUNNING", "IDLE", "STARTING", "STOPPING", "STOPPED", "UNKNOWN"];

/// What the manager asks of a mita daemon (the main one or a lane slot).
pub trait Mita: Send + Sync {
    fn version(&self) -> Result<String>;
    fn observe(&self) -> Result<Map<String, Value>>;
    fn apply(&self, config: &Value) -> Result<()>;
    fn reload(&self) -> Result<()>;
    fn stop(&self) -> Result<()>;
    fn start(&self) -> Result<()>;
    fn status(&self) -> Result<String>;
    /// Cumulative payload bytes per user since the daemon started: `(upload, download)`.
    fn traffic(&self) -> Result<BTreeMap<String, (u64, u64)>>;
    fn probe(&self) -> Result<()> {
        if self.status()? != "RUNNING" {
            return Err(Error::mita("mita is not running"));
        }
        Ok(())
    }
    /// The bound of a backup the transaction reads back.
    fn max_output(&self) -> usize {
        DEFAULT_MAX_OUTPUT
    }
}

/// The identity of an executable file: a write or a swap moves one of these, and the change
/// time cannot be set back from userspace.
type Stamp = (u64, u64, u64, u32, i64, i64);
type VerbKey = (u64, u64, u64, i64);

pub struct MitaCli {
    pub executable: PathBuf,
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_output: usize,
    pub expected_sha256: Option<String>,
    write_verb: Mutex<Option<(VerbKey, &'static str)>>,
    verified_stamp: Mutex<Option<Stamp>>,
    /// How many times the pinned executable was hashed (tests).
    pub hashed: AtomicUsize,
}

impl MitaCli {
    pub fn new(executable: impl Into<PathBuf>, env: Vec<(String, String)>, expected_sha256: Option<String>) -> Self {
        Self {
            executable: executable.into(),
            env,
            timeout: Duration::from_secs(10),
            max_output: DEFAULT_MAX_OUTPUT,
            expected_sha256,
            write_verb: Mutex::new(None),
            verified_stamp: Mutex::new(None),
            hashed: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub fn with_limits(mut self, timeout: Duration, max_output: usize) -> Self {
        self.timeout = timeout;
        self.max_output = max_output;
        self
    }

    /// The verb that stores a config as a whole. Up to 3.37 `apply config` did; 3.38 made it
    /// merge into the stored config and added `replace config` for that. Asked of the binary
    /// itself, once per executable file.
    fn whole_config_verb(&self) -> Result<&'static str> {
        let info = std::fs::metadata(&self.executable).map_err(|_| Error::mita("mita operation unavailable"))?;
        let key = (info.dev(), info.ino(), info.size(), info.mtime() * 1_000_000_000 + info.mtime_nsec());
        if let Some((known, verb)) = *self.write_verb.lock().unwrap_or_else(|e| e.into_inner()) {
            if known == key {
                return Ok(verb);
            }
        }
        // No readable help: the older verb; the readback still guards the write.
        let text =
            self.run(&["help"], None, true).map(|out| String::from_utf8_lossy(&out).into_owned()).unwrap_or_default();
        let offers_replace = text.split('\n').any(|line| {
            line.trim_start()
                .strip_prefix("replace config")
                .is_some_and(|after| after.chars().next().is_none_or(|c| !(c.is_alphanumeric() || c == '_')))
        });
        let verb = if offers_replace { "replace" } else { "apply" };
        *self.write_verb.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, verb));
        Ok(verb)
    }

    pub fn verify_executable(&self) -> Result<()> {
        let Some(expected) = &self.expected_sha256 else { return Ok(()) };
        if !util::is_hex64(expected) {
            return Err(Error::mita("invalid pinned mita executable digest"));
        }
        let unavailable = || Error::mita("pinned mita executable is unavailable");
        let info = std::fs::symlink_metadata(&self.executable).map_err(|_| unavailable())?;
        if !info.file_type().is_file() || info.permissions().mode() & 0o111 == 0 {
            return Err(unavailable());
        }
        // The panel asks for status and traffic every second: hashing the binary each time was
        // most of this manager's CPU. The pin is rechecked whenever the file is touched at all.
        let stamp = (
            info.dev(),
            info.ino(),
            info.size(),
            info.mode(),
            info.mtime() * 1_000_000_000 + info.mtime_nsec(),
            info.ctime() * 1_000_000_000 + info.ctime_nsec(),
        );
        let mut verified = self.verified_stamp.lock().unwrap_or_else(|e| e.into_inner());
        if *verified == Some(stamp) {
            return Ok(());
        }
        self.hashed.fetch_add(1, Ordering::SeqCst);
        let mut file = File::open(&self.executable).map_err(|_| unavailable())?;
        let mut digest = Sha256::new();
        let mut chunk = vec![0u8; 1024 * 1024];
        loop {
            match file.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => digest.update(&chunk[..n]),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(unavailable()),
            }
        }
        let actual = util::hex(&digest.finalize());
        if !pc_common::constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
            return Err(Error::mita("pinned mita executable digest mismatch"));
        }
        *verified = Some(stamp);
        Ok(())
    }

    /// An anonymous file holding `payload`, readable through `/proc/self/fd/<fd>`.
    fn anonymous_file(payload: &[u8]) -> io::Result<File> {
        let dir = std::env::temp_dir();
        let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
        // SAFETY: a plain open(2) of a NUL-terminated path; the fd is owned by the File below.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC, 0o600) };
        let mut file = if fd >= 0 {
            // SAFETY: `fd` was just opened and is not owned elsewhere.
            unsafe { File::from_raw_fd(fd) }
        } else {
            // Without O_TMPFILE support: a private file unlinked at once, as tempfile does.
            let name = dir.join(format!(
                ".mita-input-{}-{}",
                std::process::id(),
                util::hex(&util::random_bytes(8).unwrap_or_default())
            ));
            let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&name)?;
            let _ = std::fs::remove_file(&name);
            file
        };
        file.write_all(payload)?;
        file.flush()?;
        file.rewind()?;
        Ok(file)
    }

    /// Runs mita with `args` (and a config through a passed file), bounded by the timeout and
    /// the output cap; returns stdout when `output`.
    fn run(&self, args: &[&str], input: Option<&Value>, output: bool) -> Result<Vec<u8>> {
        self.verify_executable()?;
        let unavailable = || Error::mita("mita operation unavailable");
        let mut command = Command::new(&self.executable);
        command.args(args);
        let input_file = match input {
            Some(value) => {
                let payload = pyjson::canonical(value).into_bytes();
                if payload.len() > self.max_output {
                    return Err(Error::mita("configuration is too large"));
                }
                let file = Self::anonymous_file(&payload).map_err(|_| unavailable())?;
                command.arg(format!("/proc/self/fd/{}", file.as_raw_fd()));
                Some(file)
            }
            None => None,
        };
        let passed = input_file.as_ref().map(|f| f.as_raw_fd());
        command.envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(fd) = passed {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = spawn(&mut command).map_err(|_| unavailable())?;
        let result = self.collect(&mut child);
        drop(input_file);
        let stdout = match result {
            Ok(stdout) => stdout,
            Err(err) => {
                kill_group(child.id());
                if wait_until(&mut child, Instant::now() + Duration::from_secs(1)).is_none() {
                    return Err(unavailable());
                }
                return Err(err);
            }
        };
        let deadline = stdout.1;
        let Some(status) = wait_until(&mut child, deadline) else {
            kill_group(child.id());
            let _ = wait_until(&mut child, Instant::now() + Duration::from_secs(1));
            return Err(unavailable());
        };
        // The direct child is gone; whatever it left in its group goes with it.
        // SAFETY: killpg with a pid this process spawned as a session leader.
        if unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) } < 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        {
            return Err(unavailable());
        }
        if !status.success() {
            return Err(Error::mita("mita operation failed"));
        }
        Ok(if output { stdout.0 } else { Vec::new() })
    }

    /// Reads both pipes to EOF within the deadline and the output cap; returns stdout and the
    /// deadline left for the exit.
    fn collect(&self, child: &mut Child) -> Result<(Vec<u8>, Instant)> {
        let unavailable = || Error::mita("mita operation unavailable");
        let mut pipes: Vec<(i32, bool, Box<dyn Read>)> = Vec::new();
        if let Some(out) = child.stdout.take() {
            pipes.push((out.as_raw_fd(), true, Box::new(out)));
        }
        if let Some(err) = child.stderr.take() {
            pipes.push((err.as_raw_fd(), false, Box::new(err)));
        }
        for (fd, _, _) in &pipes {
            // SAFETY: fcntl on a pipe fd this process owns.
            unsafe {
                let flags = libc::fcntl(*fd, libc::F_GETFL);
                libc::fcntl(*fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        let deadline = Instant::now() + self.timeout;
        let mut stdout = Vec::new();
        let mut total = 0usize;
        let mut chunk = vec![0u8; 65_536.min(self.max_output + 1)];
        while !pipes.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(unavailable());
            }
            let mut polls: Vec<libc::pollfd> =
                pipes.iter().map(|(fd, _, _)| libc::pollfd { fd: *fd, events: libc::POLLIN, revents: 0 }).collect();
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: `polls` is a live array of pollfd of the given length.
            let ready = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, millis) };
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable());
            }
            if ready == 0 {
                return Err(unavailable());
            }
            let mut closed = Vec::new();
            for (index, poll) in polls.iter().enumerate() {
                if poll.revents == 0 {
                    continue;
                }
                let (_, is_stdout, reader) = &mut pipes[index];
                match reader.read(&mut chunk) {
                    Ok(0) => closed.push(index),
                    Ok(n) => {
                        total += n;
                        if total > self.max_output {
                            return Err(Error::mita("mita response is too large"));
                        }
                        if *is_stdout {
                            stdout.extend_from_slice(&chunk[..n]);
                        }
                    }
                    Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                    Err(_) => closed.push(index),
                }
            }
            for index in closed.into_iter().rev() {
                pipes.remove(index);
            }
        }
        Ok((stdout, deadline))
    }

    fn text(&self, args: &[&str]) -> Result<String> {
        let out = self.run(args, None, true)?;
        let text = String::from_utf8(out).map_err(|_| Error::mita("mita returned invalid output"))?;
        Ok(pc_common::pytext::strip(&text).to_string())
    }
}

#[cfg(not(test))]
fn spawn(command: &mut Command) -> io::Result<Child> {
    command.spawn()
}

/// Tests write their fake mita scripts while other tests fork: a child forked in between holds
/// the script open for writing until it execs, and exec answers ETXTBSY. Only the tests retry.
#[cfg(test)]
fn spawn(command: &mut Command) -> io::Result<Child> {
    let mut attempts = 0;
    loop {
        match command.spawn() {
            Err(err) if err.raw_os_error() == Some(libc::ETXTBSY) && attempts < 100 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

fn kill_group(pid: u32) {
    // SAFETY: killpg with the group of a child this process started in its own session.
    unsafe {
        libc::killpg(pid as i32, libc::SIGKILL);
    }
}

fn wait_until(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => return None,
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    }
}

/// `mita server status is "<STATE>"`, exactly.
pub fn parse_status(text: &str) -> Result<String> {
    text.strip_prefix("mita server status is \"")
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|state| STATUSES.contains(state))
        .map(str::to_string)
        .ok_or_else(|| Error::mita("mita returned invalid status"))
}

/// `mita get metrics`: `{"users": {name: {"UploadBytes", "DownloadBytes"}}}`.
pub fn parse_traffic(text: &str) -> Result<BTreeMap<String, (u64, u64)>> {
    let bad = || Error::mita("mita returned invalid metrics");
    let value: Value = serde_json::from_str(text).map_err(|_| bad())?;
    let users = match &value {
        Value::Object(map) => match map.get("users") {
            None => return Ok(BTreeMap::new()),
            Some(Value::Object(users)) => users,
            Some(_) => return Err(bad()),
        },
        _ => return Err(bad()),
    };
    let mut out = BTreeMap::new();
    for (name, row) in users {
        let Value::Object(row) = row else { return Err(bad()) };
        let count = |key: &str| match row.get(key) {
            None => Some(0),
            Some(v) => pc_common::pyvalue::strict_int(v).filter(|n| *n >= 0).and_then(|n| u64::try_from(n).ok()),
        };
        let (Some(up), Some(down)) = (count("UploadBytes"), count("DownloadBytes")) else { return Err(bad()) };
        out.insert(name.clone(), (up, down));
    }
    Ok(out)
}

impl Mita for MitaCli {
    fn version(&self) -> Result<String> {
        let text = self.text(&["version"])?;
        Ok(text.strip_prefix("mita ").unwrap_or(&text).to_string())
    }

    fn observe(&self) -> Result<Map<String, Value>> {
        let text = self.text(&["describe", "config"])?;
        match serde_json::from_str(&text) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(Error::mita("mita returned invalid configuration")),
        }
    }

    fn apply(&self, config: &Value) -> Result<()> {
        let verb = self.whole_config_verb()?;
        self.run(&[verb, "config"], Some(config), false).map(drop)
    }

    fn reload(&self) -> Result<()> {
        self.run(&["reload"], None, false).map(drop)
    }

    fn stop(&self) -> Result<()> {
        self.run(&["stop"], None, false).map(drop)
    }

    fn start(&self) -> Result<()> {
        self.run(&["start"], None, false).map(drop)
    }

    fn status(&self) -> Result<String> {
        parse_status(&self.text(&["status"])?)
    }

    fn traffic(&self) -> Result<BTreeMap<String, (u64, u64)>> {
        parse_traffic(&self.text(&["get", "metrics"])?)
    }

    fn max_output(&self) -> usize {
        self.max_output
    }
}

impl std::fmt::Debug for MitaCli {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitaCli").field("executable", &self.executable).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::tempdir;
    use serde_json::json;
    use std::path::Path;

    fn script(path: &Path, body: &str) -> PathBuf {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_path_buf()
    }

    fn env(pairs: &[(&str, &Path)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.display().to_string())).collect()
    }

    fn status_cli(dir: &Path, output: &str) -> MitaCli {
        MitaCli::new(script(&dir.join("mita-status"), &format!("#!/bin/sh\nprintf '%s\\n' '{output}'\n")), vec![], None)
    }

    fn process_running(pid: i32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat.rsplit(')').next().and_then(|rest| rest.split_whitespace().next()) != Some("Z"),
            Err(_) => false,
        }
    }

    fn gone_within_a_second(pid: i32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(1);
        while process_running(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        !process_running(pid)
    }

    #[test]
    fn cli_parses_official_exact_status_grammar() {
        for status in STATUSES {
            let dir = tempdir(&format!("status-{status}"));
            assert_eq!(status_cli(&dir, &format!("mita server status is \"{status}\"")).status().unwrap(), status);
        }
    }

    #[test]
    fn cli_rejects_ambiguous_or_noncanonical_status() {
        for (i, output) in [
            "RUNNING",
            "mita server status is \"PAUSED\"",
            "mita server status is \"RUNNING\" trailing",
            "prefix mita server status is \"RUNNING\"",
            "mita server status is \"RUNNING\"\nmita server status is \"STOPPED\"",
        ]
        .iter()
        .enumerate()
        {
            let dir = tempdir(&format!("status-bad-{i}"));
            assert_eq!(status_cli(&dir, output).status().unwrap_err(), Error::mita("mita returned invalid status"));
        }
    }

    #[test]
    fn cli_refuses_unpinned_or_changed_executable_before_launch() {
        let dir = tempdir("pinned");
        let marker = dir.join("launched");
        let fake = script(&dir.join("mita"), "#!/bin/sh\nprintf launched > \"$MARKER\"\nprintf 'mita 3.35.0\\n'\n");
        let digest = util::sha256_hex(&std::fs::read(&fake).unwrap());
        let pinned = MitaCli::new(&fake, env(&[("MARKER", &marker)]), Some(digest.clone()));
        assert_eq!(pinned.version().unwrap(), "3.35.0");
        std::fs::remove_file(&marker).unwrap();
        let wrong = MitaCli::new(&fake, env(&[("MARKER", &marker)]), Some("0".repeat(64)));
        let error = wrong.version().unwrap_err();
        assert!(error.message().contains("digest"));
        assert!(!marker.exists());
        assert!(!error.message().contains(&digest));
        let malformed = MitaCli::new(&fake, vec![], Some("XYZ".into()));
        assert_eq!(malformed.version().unwrap_err(), Error::mita("invalid pinned mita executable digest"));
    }

    #[test]
    fn cli_hashes_an_unchanged_executable_once_and_any_change_again() {
        let dir = tempdir("hash-once");
        let fake = script(&dir.join("mita"), "#!/bin/sh\nprintf 'mita 3.35.0\\n'\n");
        let cli = MitaCli::new(&fake, vec![], Some(util::sha256_hex(&std::fs::read(&fake).unwrap())));
        for _ in 0..5 {
            cli.verify_executable().unwrap();
        }
        assert_eq!(cli.hashed.load(Ordering::SeqCst), 1);
        // Same size, new bytes in place: the stamp (mtime/ctime) moves, so the pin is checked again.
        std::thread::sleep(Duration::from_millis(50)); // file times tick with the kernel's coarse clock
        std::fs::write(&fake, "#!/bin/sh\nprintf 'mita 3.35.1\\n'\n").unwrap();
        assert!(cli.verify_executable().unwrap_err().message().contains("digest mismatch"));
        // A file swapped in under the same name is a new inode: checked again, refused again.
        let swapped = script(&dir.join("other"), "#!/bin/sh\nexit 0\n");
        std::fs::rename(&swapped, &fake).unwrap();
        assert!(cli.verify_executable().unwrap_err().message().contains("digest mismatch"));
        assert_eq!(cli.hashed.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn cli_passes_complete_config_through_anonymous_fd_and_bounds_output() {
        let dir = tempdir("anonymous-fd");
        let log = dir.join("argv.json");
        let fake = script(
            &dir.join("mita"),
            r#"#!/usr/bin/python3
import json, os, sys
with open(os.environ['ARGV_LOG'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\n')
if sys.argv[1:] == ['version']: print('mita 3.35.0')
elif sys.argv[1:2] == ['apply']:
    assert sys.argv[2] == 'config' and sys.argv[3].startswith('/proc/self/fd/')
    json.load(open(sys.argv[3]))
elif sys.argv[1:] == ['describe', 'config']: print(json.dumps({'portBindings':[{'port':8443,'protocol':'TCP'}],'users':[]}))
elif sys.argv[1:] == ['status']: print('RUNNING')
elif sys.argv[1:] == ['get', 'metrics']: print(json.dumps({'users':[]}))
"#,
        );
        let cli = MitaCli::new(&fake, env(&[("ARGV_LOG", &log)]), None).with_limits(Duration::from_secs(2), 4096);
        cli.apply(&json!({"portBindings": [{"port": 8443, "protocol": "TCP"}], "users": [{"name": "alice", "password": "not-on-argv"}]}))
            .unwrap();
        let lines = std::fs::read_to_string(&log).unwrap();
        assert!(!lines.contains("not-on-argv") && lines.contains("/proc/self/fd/"));
        assert_eq!(cli.observe().unwrap()["portBindings"][0]["port"], 8443);
        let huge = json!({"users": [{"name": "x".repeat(5000)}]});
        assert_eq!(cli.apply(&huge).unwrap_err(), Error::mita("configuration is too large"));
    }

    #[test]
    fn cli_writes_the_whole_config_with_the_verb_the_binary_offers() {
        for (i, (help, verb)) in [
            // mita 3.38 made `apply config` merge into the stored config; the whole-config write
            // the manager needs moved to `replace config`.
            ("  apply config <JSON_FILE>\\n  replace config <JSON_FILE>\\n  describe config", "replace"),
            // Up to 3.37 `apply config` stored the sent config as a whole.
            ("  apply config <JSON_FILE>\\n  describe config", "apply"),
        ]
        .iter()
        .enumerate()
        {
            let dir = tempdir(&format!("verb-{i}"));
            let log = dir.join("argv.json");
            let fake = script(
                &dir.join("mita"),
                &format!(
                    r#"#!/usr/bin/python3
import json, os, sys
with open(os.environ['ARGV_LOG'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\n')
if sys.argv[1:] == ['help']: print("{help}")
elif sys.argv[1:2] in (['apply'], ['replace']):
    assert sys.argv[2] == 'config' and sys.argv[3].startswith('/proc/self/fd/')
    json.load(open(sys.argv[3]))
else: raise SystemExit(8)
"#
                ),
            );
            let cli = MitaCli::new(&fake, env(&[("ARGV_LOG", &log)]), None).with_limits(Duration::from_secs(2), 4096);
            let config = json!({"portBindings": [{"port": 8443, "protocol": "TCP"}]});
            cli.apply(&config).unwrap();
            cli.apply(&config).unwrap();
            let calls: Vec<Value> = std::fs::read_to_string(&log)
                .unwrap()
                .lines()
                .map(|line| {
                    let args: Vec<Value> = serde_json::from_str(line).unwrap();
                    Value::Array(args.into_iter().take(2).collect())
                })
                .collect();
            assert_eq!(calls, [json!(["help"]), json!([verb, "config"]), json!([verb, "config"])]);
        }
    }

    #[test]
    fn cli_kills_child_during_execution_when_either_output_stream_exceeds_cap() {
        for stream in ["stdout", "stderr"] {
            let dir = tempdir(&format!("overflow-{stream}"));
            let marker = dir.join("completed");
            let fake = script(
                &dir.join("mita-overflow"),
                &format!(
                    "#!/usr/bin/python3\nimport os, sys\nout = sys.{stream}.buffer\nfor _ in range(2048):\n    \
                     out.write(b'x' * 1024); out.flush()\nopen(os.environ['MARKER'], 'w').write('child completed')\n"
                ),
            );
            let cli = MitaCli::new(&fake, env(&[("MARKER", &marker)]), None).with_limits(Duration::from_secs(2), 1024);
            assert!(cli.version().unwrap_err().message().contains("too large"));
            assert!(!marker.exists());
        }
    }

    #[test]
    fn cli_timeout_kills_descendant_that_inherits_output_pipes() {
        let dir = tempdir("timeout-descendant");
        let pid_file = dir.join("grandchild.pid");
        let fake = script(
            &dir.join("mita-descendant"),
            "#!/usr/bin/python3\nimport os, subprocess, sys\nsubprocess.Popen([sys.executable, '-c', \
             'import os,time; open(os.environ[\"PID_FILE\"],\"w\").write(str(os.getpid())); time.sleep(60)'])\n",
        );
        // Both interpreters must start before the deadline can exercise orphan cleanup.
        let cli = MitaCli::new(&fake, env(&[("PID_FILE", &pid_file)]), None).with_limits(Duration::from_secs(1), 1024);
        assert!(cli.version().unwrap_err().message().contains("operation unavailable"));
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        assert!(gone_within_a_second(pid));
    }

    #[test]
    fn cli_success_kills_same_group_descendant_after_direct_child_exits() {
        let dir = tempdir("success-descendant");
        let pid_file = dir.join("success-grandchild.pid");
        let fake = script(
            &dir.join("mita-success-descendant"),
            "#!/usr/bin/python3\nimport os, subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', \
             'import os,time; open(os.environ[\"PID_FILE\"],\"w\").write(str(os.getpid())); time.sleep(60)'], \
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n\
             while not os.path.exists(os.environ['PID_FILE']): time.sleep(0.001)\nprint('mita 3.35.0', flush=True)\n",
        );
        let cli = MitaCli::new(&fake, env(&[("PID_FILE", &pid_file)]), None).with_limits(Duration::from_secs(2), 1024);
        assert_eq!(cli.version().unwrap(), "3.35.0");
        // The grandchild may not have written its pid before it was killed.
        let pid: i32 = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = text.parse() {
                    break pid;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(gone_within_a_second(pid));
    }

    #[test]
    fn cli_eof_before_child_exit_is_sanitized_and_reaps_child() {
        let dir = tempdir("eof-hang");
        let pid_file = dir.join("child.pid");
        let fake = script(
            &dir.join("mita-eof-hang"),
            "#!/usr/bin/python3\nimport os,time\nopen(os.environ['PID_FILE'],'w').write(str(os.getpid()))\n\
             os.close(1); os.close(2); time.sleep(60)\n",
        );
        let cli =
            MitaCli::new(&fake, env(&[("PID_FILE", &pid_file)]), None).with_limits(Duration::from_millis(100), 1024);
        // A slow interpreter start can meet the deadline before the pid file is written.
        let error = cli.version().unwrap_err();
        assert_eq!(error, Error::mita("mita operation unavailable"));
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            assert!(!process_running(text.parse().unwrap()));
        }
    }

    fn traffic_cli(dir: &Path, output: &str) -> MitaCli {
        let body =
            format!("#!/bin/sh\n[ \"$1 $2\" = \"get metrics\" ] || exit 8\ncat <<'EOF_JSON'\n{output}\nEOF_JSON\n");
        MitaCli::new(script(&dir.join("mita-traffic"), &body), vec![], None)
    }

    #[test]
    fn cli_reads_cumulative_per_user_bytes_from_mita_get_metrics() {
        let dir = tempdir("traffic-cli");
        let output = json!({
            "traffic": {"DownloadBytes": 9, "UploadBytes": 1},
            "users": {"alice": {"DownloadBytes": 3881224570u64, "UploadBytes": 14635}, "bob": {"UploadBytes": 7}},
        });
        let traffic = traffic_cli(&dir, &output.to_string()).traffic().unwrap();
        assert_eq!(traffic, BTreeMap::from([("alice".into(), (14635, 3881224570)), ("bob".into(), (7, 0))]));
    }

    #[test]
    fn cli_traffic_is_empty_before_any_user_has_carried_bytes() {
        let dir = tempdir("traffic-empty");
        assert!(traffic_cli(&dir, "{\"traffic\": {}}").traffic().unwrap().is_empty());
    }

    #[test]
    fn cli_traffic_refuses_output_it_does_not_understand() {
        for (i, output) in [
            "not json",
            "[]",
            "{\"users\": []}",
            "{\"users\": {\"a\": []}}",
            "{\"users\": {\"a\": {\"UploadBytes\": -1}}}",
            "{\"users\": {\"a\": {\"UploadBytes\": true}}}",
            "{\"users\": {\"a\": {\"DownloadBytes\": \"5\"}}}",
        ]
        .iter()
        .enumerate()
        {
            let dir = tempdir(&format!("traffic-bad-{i}"));
            assert!(matches!(traffic_cli(&dir, output).traffic(), Err(Error::Mita(_))), "{output}");
        }
    }
}
