//! Subprocesses with a hard deadline, the equivalent of `subprocess.run(…, timeout=…)`.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Output {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Output {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug)]
pub enum RunError {
    /// The program could not be started (missing binary, permissions).
    Spawn(io::Error),
    /// The deadline passed; the process was killed. Carries what it wrote so far.
    Timeout {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(err) => write!(f, "cannot start command: {err}"),
            RunError::Timeout { .. } => write!(f, "command timed out"),
            RunError::Io(err) => write!(f, "command I/O failed: {err}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Runs `argv` with optional stdin, capturing both streams, killing it at `timeout`.
pub fn run(argv: &[&str], stdin: Option<&[u8]>, timeout: Duration) -> Result<Output, RunError> {
    let mut command = Command::new(argv.first().copied().unwrap_or(""));
    command.args(&argv[1..]);
    run_command(command, stdin, timeout)
}

pub fn run_command(mut command: Command, stdin: Option<&[u8]>, timeout: Duration) -> Result<Output, RunError> {
    command
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    let writer = stdin.map(|data| {
        let mut pipe = child.stdin.take().expect("stdin is piped");
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        })
    });
    let mut out_pipe = child.stdout.take().expect("stdout is piped");
    let mut err_pipe = child.stderr.take().expect("stderr is piped");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(RunError::Io)? {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    match status {
        Some(status) => Ok(Output { status, stdout, stderr }),
        None => Err(RunError::Timeout { stdout, stderr }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_stdin() {
        let out = run(&["sh", "-c", "cat; echo err >&2; exit 3"], Some(b"hello"), Duration::from_secs(5)).unwrap();
        assert_eq!(out.stdout, b"hello");
        assert_eq!(out.stderr_text(), "err\n");
        assert_eq!(out.status.code(), Some(3));
    }

    #[test]
    fn kills_at_the_deadline() {
        let started = Instant::now();
        let err = run(&["sleep", "5"], None, Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, RunError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn missing_binary_is_a_spawn_error() {
        assert!(matches!(run(&["/nonexistent/bin"], None, Duration::from_secs(1)), Err(RunError::Spawn(_))));
    }
}
