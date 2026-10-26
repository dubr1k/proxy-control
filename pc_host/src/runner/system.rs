//! The real host runner: `fork` + `setsid` + `exec`, `poll(2)` on the pipes, `killpg(SIGKILL)`
//! and a `/proc` scan that proves a killed group is gone.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{
    capture_text, capture_unavailable, interrupt_flag, validate_argv, Bounded, BoundedError, BoundedOutput, Capture,
    HostRunner, QueryError, RunError, RunOptions, RunOutput, QUERY_MAX_CHARS,
};
use crate::error::os_error_class;
use crate::pytext::text_mode;

/// Commands on this host, run as the Python installer ran them.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

/// How often a wait wakes up to look at the interrupt flag.
const TICK: Duration = Duration::from_millis(20);
/// The most stderr a mutating command keeps (its tail); callers show at most 900 characters.
const STDERR_KEEP: usize = 8 * 1024 * 1024;

fn command(argv: &[&str]) -> Command {
    let mut command = Command::new(argv[0]);
    command.args(&argv[1..]);
    // SAFETY: `setsid` is async-signal-safe; nothing else runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

/// Python's `returncode`: the exit code, or `-signal`.
fn returncode(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(0))
}

fn kill_group(pid: u32) {
    // SAFETY: plain syscall; ESRCH (group already gone) is fine.
    unsafe {
        libc::killpg(pid as libc::pid_t, libc::SIGKILL);
    }
}

/// Kills the child's group and reaps the leader (`_terminate_process`).
fn terminate(child: &mut Child) {
    kill_group(child.id());
    let _ = child.wait();
}

/// Waits up to `timeout` for `fd` to become readable (or hung up); `false` on timeout or EINTR.
fn readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one valid pollfd.
    let rc = unsafe { libc::poll(&mut poll, 1, millis) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::Interrupted { Ok(false) } else { Err(err) };
    }
    Ok(rc > 0)
}

fn read_some(stream: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match stream.read(buffer) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// Keeps the last `keep` bytes of a growing buffer.
fn keep_tail(buffer: &mut Vec<u8>, keep: usize) {
    if buffer.len() > keep.saturating_mul(2) {
        let cut = buffer.len() - keep;
        buffer.drain(..cut);
    }
}

/// Reads one pipe to EOF or `deadline`, feeding `sink`; `Ok(false)` when the deadline came
/// first.
fn drain(stream: &mut File, deadline: Instant, sink: &mut dyn FnMut(&[u8])) -> io::Result<bool> {
    let mut buffer = vec![0u8; 65536];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        if !readable(stream.as_raw_fd(), deadline - now)? {
            continue;
        }
        let read = read_some(stream, &mut buffer)?;
        if read == 0 {
            return Ok(true);
        }
        sink(&buffer[..read]);
    }
}

/// Reaps the child before `deadline`; `None` when it is still running.
fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
    }
}

/// `_wait_process_group_stopped`: until no live (`Z`/`X` excluded) process of `group` is left
/// in `/proc`, at most one second. `/proc` must be this process's procfs (fail closed).
pub fn wait_process_group_stopped(group: i32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let own = std::fs::read_to_string("/proc/self/stat").map_err(|_| "process observation is unavailable")?;
    if own.split(' ').next().and_then(|pid| pid.parse::<u32>().ok()) != Some(std::process::id()) {
        return Err("process observation is unavailable".into());
    }
    loop {
        let mut active = false;
        let entries = std::fs::read_dir("/proc").map_err(|_| "process observation is unavailable")?;
        for entry in entries {
            let entry = entry.map_err(|_| "process observation is unavailable")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let text = match std::fs::read_to_string(entry.path().join("stat")) {
                Ok(text) => text,
                Err(err) if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH) => {
                    continue
                }
                Err(err) => return Err(format!("process observation failed: {err}")),
            };
            let Some((_, rest)) = text.rsplit_once(')') else { continue };
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() > 2 && fields[2].parse::<i32>().ok() == Some(group) && !matches!(fields[0], "Z" | "X") {
                active = true;
                break;
            }
        }
        if !active {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("command process group did not stop after SIGKILL".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

enum Stop {
    TimedOut,
    Interrupted,
    Io(io::Error),
}

impl SystemRunner {
    /// The kill-and-prove path of `_DefaultCoreRunner.run` after a timeout, interrupt or
    /// read error.
    fn stop_core(child: &mut Child, stderr: &mut Option<File>, buffer: &mut Vec<u8>, stop: Stop) -> RunError {
        kill_group(child.id());
        let drain_deadline = Instant::now() + Duration::from_secs(1);
        let mut drained = true;
        if let Some(stream) = stderr.as_mut() {
            let mut sink = |chunk: &[u8]| {
                buffer.extend_from_slice(chunk);
                keep_tail(buffer, STDERR_KEEP);
            };
            drained = matches!(drain(stream, drain_deadline, &mut sink), Ok(true));
        }
        *stderr = None;
        let reaped = if drained {
            match wait_until(child, drain_deadline) {
                Ok(Some(_)) => true,
                // `communicate(timeout=1.0)` expired: one more second for the leader.
                Ok(None) => matches!(wait_until(child, Instant::now() + Duration::from_secs(1)), Ok(Some(_))),
                Err(_) => false,
            }
        } else {
            // A daemon escaped the group and keeps the pipe; do not wait for its EOF.
            matches!(wait_until(child, Instant::now() + Duration::from_secs(1)), Ok(Some(_)))
        };
        if !reaped || wait_process_group_stopped(child.id() as i32).is_err() {
            return RunError::CleanupUnconfirmed;
        }
        let stderr =
            if buffer.len() > STDERR_KEEP { buffer[buffer.len() - STDERR_KEEP..].to_vec() } else { buffer.clone() };
        match stop {
            Stop::TimedOut => RunError::TimedOut { stderr },
            Stop::Interrupted => RunError::Interrupted { stderr },
            Stop::Io(err) => RunError::Io(err),
        }
    }
}

impl HostRunner for SystemRunner {
    fn bounded(&self, argv: &[&str], limits: Bounded) -> Result<BoundedOutput, BoundedError> {
        validate_argv(argv)?;
        let cancel = interrupt_flag();
        let mut child =
            command(argv).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(
                |err| {
                    if err.kind() == io::ErrorKind::NotFound {
                        BoundedError::Unavailable
                    } else {
                        BoundedError::CouldNotExecute
                    }
                },
            )?;
        let deadline = Instant::now() + limits.timeout;
        let mut streams: [Option<File>; 2] = [
            child.stdout.take().map(|s| File::from(std::os::fd::OwnedFd::from(s))),
            child.stderr.take().map(|s| File::from(std::os::fd::OwnedFd::from(s))),
        ];
        let mut chunks: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        let mut captured = 0usize;
        let mut buffer = vec![0u8; 65536];
        let fail = |child: &mut Child, error: BoundedError| {
            terminate(child);
            Err(error)
        };
        while streams.iter().any(Option::is_some) {
            let now = Instant::now();
            if now >= deadline {
                return fail(&mut child, BoundedError::TimedOut);
            }
            if cancel.load(Ordering::SeqCst) {
                return fail(&mut child, BoundedError::Interrupted);
            }
            let mut polls: Vec<libc::pollfd> = Vec::new();
            let mut owners = Vec::new();
            for (index, stream) in streams.iter().enumerate() {
                if let Some(stream) = stream {
                    polls.push(libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 });
                    owners.push(index);
                }
            }
            let wait = (deadline - now).min(TICK).as_millis() as i32;
            // SAFETY: `polls` holds valid descriptors owned by `streams`.
            let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, wait) };
            if rc < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return fail(&mut child, BoundedError::CouldNotExecute);
            }
            for (poll, index) in polls.iter().zip(owners) {
                if poll.revents == 0 {
                    continue;
                }
                let stream = streams[index].as_mut().expect("polled stream is open");
                let want = (limits.max_output - captured + 1).min(buffer.len());
                let read = match read_some(stream, &mut buffer[..want]) {
                    Ok(read) => read,
                    Err(_) => return fail(&mut child, BoundedError::CouldNotExecute),
                };
                if read == 0 {
                    streams[index] = None;
                    continue;
                }
                captured += read;
                if captured > limits.max_output {
                    return fail(&mut child, BoundedError::OutputLimit);
                }
                chunks[index].extend_from_slice(&buffer[..read]);
            }
        }
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => return fail(&mut child, BoundedError::CouldNotExecute),
            }
            if Instant::now() >= deadline {
                return fail(&mut child, BoundedError::TimedOut);
            }
            if cancel.load(Ordering::SeqCst) {
                return fail(&mut child, BoundedError::Interrupted);
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let stdout = String::from_utf8_lossy(&chunks[0]).into_owned();
        let stderr = String::from_utf8_lossy(&chunks[1]).into_owned();
        // `_output_size` measures the decoded text re-encoded, replacement characters included.
        if stdout.len() + stderr.len() > limits.max_output {
            return Err(BoundedError::OutputLimit);
        }
        Ok(BoundedOutput { returncode: returncode(status), stdout, stderr })
    }

    fn run(&self, argv: &[&str], options: &RunOptions<'_>) -> Result<RunOutput, RunError> {
        if argv.is_empty() {
            return Err(RunError::Spawn(io::Error::new(io::ErrorKind::InvalidInput, "empty argv")));
        }
        let stdin = match &options.stdin_path {
            Some(path) => Stdio::from(File::open(path).map_err(RunError::Stdin)?),
            None => Stdio::null(),
        };
        let mut command = command(argv);
        command.stdin(stdin).stdout(Stdio::null()).stderr(Stdio::piped());
        if let Some(env) = &options.env {
            command.env_clear();
            command.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        let mut child = command.spawn().map_err(RunError::Spawn)?;
        drop(command);
        let mut stderr = child.stderr.take().map(|s| File::from(std::os::fd::OwnedFd::from(s)));
        let deadline = Instant::now() + options.timeout;
        let cancel: &AtomicBool = options.cancel;
        let mut buffer = Vec::new();
        let mut chunk = vec![0u8; 65536];
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err(Self::stop_core(&mut child, &mut stderr, &mut buffer, Stop::Interrupted));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Self::stop_core(&mut child, &mut stderr, &mut buffer, Stop::TimedOut));
            }
            let wait = (deadline - now).min(TICK);
            match stderr.as_mut() {
                Some(stream) => {
                    let ready = match readable(stream.as_raw_fd(), wait) {
                        Ok(ready) => ready,
                        Err(err) => return Err(Self::stop_core(&mut child, &mut stderr, &mut buffer, Stop::Io(err))),
                    };
                    if !ready {
                        continue;
                    }
                    match read_some(stream, &mut chunk) {
                        Ok(0) => stderr = None,
                        Ok(read) => {
                            buffer.extend_from_slice(&chunk[..read]);
                            keep_tail(&mut buffer, STDERR_KEEP);
                        }
                        Err(err) => return Err(Self::stop_core(&mut child, &mut stderr, &mut buffer, Stop::Io(err))),
                    }
                }
                None => match child.try_wait() {
                    Ok(Some(status)) => {
                        if buffer.len() > STDERR_KEEP {
                            buffer.drain(..buffer.len() - STDERR_KEEP);
                        }
                        return Ok(RunOutput { returncode: returncode(status), stderr: buffer });
                    }
                    Ok(None) => std::thread::sleep(wait.min(Duration::from_millis(5))),
                    Err(err) => return Err(Self::stop_core(&mut child, &mut stderr, &mut buffer, Stop::Io(err))),
                },
            }
        }
    }

    fn capture(&self, argv: &[&str], max_chars: usize, limits: Capture) -> String {
        let limit = max_chars.min(limits.max_chars);
        if argv.is_empty() {
            return capture_unavailable("OSError", limit);
        }
        let (reader, writer) = match io::pipe() {
            Ok(pipe) => pipe,
            Err(err) => return capture_unavailable(os_error_class(&err), limit),
        };
        let writer_copy = match writer.try_clone() {
            Ok(copy) => copy,
            Err(err) => return capture_unavailable(os_error_class(&err), limit),
        };
        let mut command = command(argv);
        command.stdin(Stdio::null()).stdout(writer_copy).stderr(writer);
        let spawned = command.spawn();
        // The command holds our copies of the write end; the read end sees EOF only once
        // they are closed.
        drop(command);
        let mut child = match spawned {
            Ok(child) => child,
            Err(err) => return capture_unavailable(os_error_class(&err), limit),
        };
        let mut stream = File::from(std::os::fd::OwnedFd::from(reader));
        let deadline = Instant::now() + limits.timeout;
        // Enough bytes for `limit` characters after decoding; `limit == 0` keeps everything
        // (Python's `output[-0:]`).
        let keep = if limit == 0 { usize::MAX / 2 } else { limit.saturating_mul(4).saturating_add(8) };
        let mut output = Vec::new();
        let mut sink = |chunk: &[u8]| {
            output.extend_from_slice(chunk);
            keep_tail(&mut output, keep);
        };
        let finished = match drain(&mut stream, deadline, &mut sink) {
            Ok(true) => wait_until(&mut child, deadline).ok().flatten(),
            Ok(false) => None,
            Err(err) => {
                terminate(&mut child);
                return capture_unavailable(os_error_class(&err), limit);
            }
        };
        let Some(status) = finished else {
            terminate(&mut child);
            return capture_unavailable("TimeoutExpired", limit);
        };
        if output.len() > keep {
            output.drain(..output.len() - keep);
        }
        capture_text(returncode(status), &text_mode(&output), limit)
    }

    fn capture_checked(&self, argv: &[&str], timeout: Duration) -> Result<String, QueryError> {
        if argv.is_empty() {
            return Err(QueryError::Failed);
        }
        let mut child = command(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| QueryError::Failed)?;
        let mut stream = File::from(std::os::fd::OwnedFd::from(child.stdout.take().expect("stdout is piped")));
        let deadline = Instant::now() + timeout;
        let cap = QUERY_MAX_CHARS * 4 + 4;
        let mut output = Vec::new();
        let mut overflow = false;
        let mut sink = |chunk: &[u8]| {
            if output.len() + chunk.len() > cap {
                overflow = true;
            } else {
                output.extend_from_slice(chunk);
            }
        };
        let finished = match drain(&mut stream, deadline, &mut sink) {
            Ok(true) => wait_until(&mut child, deadline).ok().flatten(),
            _ => None,
        };
        let Some(status) = finished else {
            terminate(&mut child);
            return Err(QueryError::Failed);
        };
        if returncode(status) != 0 {
            return Err(QueryError::Failed);
        }
        let text = text_mode(&output);
        if overflow || text.chars().count() > QUERY_MAX_CHARS {
            return Err(QueryError::ExceededBound);
        }
        Ok(text)
    }
}
