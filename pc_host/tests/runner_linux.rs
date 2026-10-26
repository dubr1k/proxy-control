//! The real runner on Linux: ports of `tests/test_installer_core_runner_timeout.py`,
//! `tests/test_command_runner_deadline.py` and the agent runner's capture bound, plus the
//! bounded (audit) contract. Workers are `/bin/sh` scripts, so no Python is needed.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pc_host::runner::{
    bounded_capture, bounded_json, is_in_band_failure, Bounded, BoundedError, Capture, HostRunner, QueryError,
    RunError, RunOptions, SystemRunner,
};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pc-host-runner-{label}-{}", pc_host::fs::token_hex::<8>()));
        fs::create_dir(&path).unwrap();
        Scratch(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn alive(pid: i32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(text) => text.rsplit_once(')').map(|(_, rest)| rest.split_whitespace().next() != Some("Z")).unwrap_or(false),
        Err(_) => false,
    }
}

fn wait_for(path: &Path, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if path.exists() && !fs::read_to_string(path).unwrap_or_default().trim().is_empty() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn pid_of(path: &Path) -> i32 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

/// Kill a leftover worker only if it is exactly this test's worker.
fn cleanup(pid_file: &Path, marker: &str) {
    if let Ok(text) = fs::read_to_string(pid_file) {
        if let Ok(pid) = text.trim().parse::<i32>() {
            let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if alive(pid) && String::from_utf8_lossy(&cmdline).contains(marker) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
}

/// A worker that ignores SIGTERM, records its pid, and — once `rollback` exists — would
/// mutate the host by writing `late`.
const WORKER: &str = r#"trap '' TERM
[ "$4" = yes ] && exec 2>&-
echo $$ > "$1"
end=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$end" ]; do
  if [ -e "$2" ]; then echo 'unexpected mutation' > "$3"; break; fi
  sleep 0.01
done"#;

fn timeout_stops_term_ignoring_child_before_rollback(leader_exits: bool) {
    let dir = Scratch::new("timeout");
    let worker = dir.path().join("worker.sh");
    fs::write(&worker, WORKER).unwrap();
    let pid_file = dir.path().join("worker.pid");
    let rollback = dir.path().join("rollback-started");
    let late = dir.path().join("mutation-after-rollback");
    // Either the shell waits for the worker (which closed stderr), or it exits at once and the
    // worker keeps the stderr pipe.
    let shell = format!("\"$@\" &\n{}", if leader_exits { "exit 0\n" } else { "wait\n" });
    let args = [
        "/bin/sh",
        "-c",
        &shell,
        "test-shell",
        "/bin/sh",
        worker.to_str().unwrap(),
        pid_file.to_str().unwrap(),
        rollback.to_str().unwrap(),
        late.to_str().unwrap(),
        if leader_exits { "no" } else { "yes" },
    ];
    let options = RunOptions { timeout: Duration::from_secs(1), ..RunOptions::default() };
    let result = SystemRunner.run(&args, &options);
    assert!(matches!(result, Err(RunError::TimedOut { .. })), "{result:?}");
    assert!(pid_file.exists(), "the isolated worker did not start before the timeout");
    let pid = pid_of(&pid_file);
    let alive_at_return = alive(pid);
    fs::write(&rollback, b"").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    cleanup(&pid_file, worker.to_str().unwrap());
    assert!(!alive_at_return, "timed-out runner returned while its child was still running");
    assert!(!late.exists(), "a descendant mutated the host after rollback started");
}

#[test]
fn timeout_stops_term_ignoring_child_before_rollback_leader_waits() {
    timeout_stops_term_ignoring_child_before_rollback(false);
}

#[test]
fn timeout_stops_term_ignoring_child_before_rollback_leader_exits() {
    timeout_stops_term_ignoring_child_before_rollback(true);
}

#[test]
fn run_suppresses_stdout_preserves_stderr_stdin_and_env() {
    let dir = Scratch::new("streams");
    let secret = dir.path().join("private-input");
    fs::write(&secret, b"synthetic-secret").unwrap();
    let options = RunOptions {
        stdin_path: Some(secret),
        env: Some(vec![("TEST_DIAGNOSTIC".into(), "safe diagnostic".into())]),
        ..RunOptions::default()
    };
    let result = SystemRunner
        .run(
            &[
                "/bin/sh",
                "-c",
                "/bin/cat; printf %s \"$TEST_DIAGNOSTIC\" >&2; [ -z \"$HOME\" ] || echo leaked >&2; exit 3",
            ],
            &options,
        )
        .unwrap();
    assert_eq!(result.returncode, 3);
    assert_eq!(result.stderr, b"safe diagnostic");
}

#[test]
fn timeout_preserves_stderr_without_exposing_stdout() {
    let options = RunOptions { timeout: Duration::from_secs(1), ..RunOptions::default() };
    let result = SystemRunner.run(
        &["/bin/sh", "-c", "echo synthetic-private-output; printf 'safe timeout diagnostic' >&2; sleep 15"],
        &options,
    );
    match result {
        Err(RunError::TimedOut { stderr }) => assert_eq!(stderr, b"safe timeout diagnostic"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn interrupt_stops_the_process_group() {
    let dir = Scratch::new("interrupt");
    let pid_file = dir.path().join("interrupt-worker.pid");
    let flag = Arc::new(AtomicBool::new(false));
    let (watch, raise) = (pid_file.clone(), flag.clone());
    let interrupter = std::thread::spawn(move || {
        assert!(wait_for(&watch, Duration::from_secs(5)), "the isolated worker did not start");
        raise.store(true, Ordering::SeqCst);
    });
    let code = format!("trap '' TERM; exec 2>&-; echo $$ > {}; sleep 15", pid_file.display());
    let options = RunOptions { cancel: &flag, ..RunOptions::default() };
    let result = SystemRunner.run(&["/bin/sh", "-c", "\"$@\" & wait", "test-shell", "/bin/sh", "-c", &code], &options);
    interrupter.join().unwrap();
    let error = result.unwrap_err();
    assert!(matches!(error, RunError::Interrupted { .. }), "{error:?}");
    assert!(error.stops_the_engine());
    let pid = pid_of(&pid_file);
    let still = alive(pid);
    cleanup(&pid_file, "sleep");
    assert!(!still, "the interrupted group survived");
}

#[test]
fn timeout_drain_is_bounded_when_a_daemon_escapes_the_group() {
    let dir = Scratch::new("escape");
    let pid_file = dir.path().join("escaped-worker.pid");
    let code = format!("echo $$ > {}; printf 'safe escaped diagnostic' >&2; exec sleep 15", pid_file.display());
    let started = Instant::now();
    let options = RunOptions { timeout: Duration::from_secs(1), ..RunOptions::default() };
    let result =
        SystemRunner.run(&["/bin/sh", "-c", "setsid \"$@\" & wait", "test-shell", "/bin/sh", "-c", &code], &options);
    let elapsed = started.elapsed();
    cleanup(&pid_file, "sleep");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
    match result {
        Err(RunError::TimedOut { stderr }) => assert_eq!(stderr, b"safe escaped diagnostic"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn run_reports_spawn_and_stdin_failures() {
    let error = SystemRunner.run(&["/nonexistent/binary"], &RunOptions::default()).unwrap_err();
    assert_eq!(error.python_class_name(), "FileNotFoundError");
    let options = RunOptions { stdin_path: Some("/nonexistent/stdin".into()), ..RunOptions::default() };
    assert!(matches!(SystemRunner.run(&["true"], &options), Err(RunError::Stdin(_))));
    assert_eq!(SystemRunner.run(&["/bin/sh", "-c", "kill -9 $$"], &RunOptions::default()).unwrap().returncode, -9);
}

#[test]
fn children_start_in_their_own_session() {
    let dir = Scratch::new("session");
    let out = dir.path().join("ids");
    let script = format!("ps -o sid= -o pgid= -p $$ > {}", out.display());
    SystemRunner.run(&["/bin/sh", "-c", &script], &RunOptions::default()).unwrap();
    let ids = fs::read_to_string(&out).unwrap();
    let ours = std::process::id().to_string();
    assert!(!ids.split_whitespace().any(|id| id == ours), "{ids}");
    let mut parts = ids.split_whitespace();
    assert_eq!(parts.next(), parts.next(), "the child leads its own session and group");
}

// ----------------------------------------------------------------------------------------------
// Bounded (audit) contract

#[test]
fn bounded_runs_and_decodes_text() {
    let out =
        SystemRunner.bounded(&["/bin/sh", "-c", "printf 'ok\\377'; printf err >&2; exit 4"], Bounded::AUDIT).unwrap();
    assert_eq!(out.returncode, 4);
    assert_eq!(out.stdout, "ok\u{fffd}");
    assert_eq!(out.stderr, "err");
    assert_eq!(
        bounded_capture(&SystemRunner, &["/bin/sh", "-c", "exit 2"], Bounded::AUDIT),
        Err(BoundedError::Failed(2))
    );
    assert_eq!(
        bounded_json(&SystemRunner, &["/bin/sh", "-c", "echo '{\"a\": [1]}'"], Bounded::AUDIT).unwrap(),
        serde_json::json!({"a": [1]})
    );
    assert_eq!(
        bounded_json(&SystemRunner, &["/bin/sh", "-c", "echo '{'"], Bounded::AUDIT),
        Err(BoundedError::MalformedJson)
    );
}

#[test]
fn bounded_deadline_and_output_limit_kill_the_group() {
    let dir = Scratch::new("bounded");
    let pid_file = dir.path().join("child.pid");
    let script = format!("sleep 30 & echo $! > {}; wait", pid_file.display());
    let limits = Bounded::new(Duration::from_millis(500), 1024).unwrap();
    let started = Instant::now();
    assert_eq!(SystemRunner.bounded(&["/bin/sh", "-c", &script], limits), Err(BoundedError::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(wait_for(&pid_file, Duration::from_secs(1)));
    std::thread::sleep(Duration::from_millis(100));
    let pid = pid_of(&pid_file);
    let still = alive(pid);
    cleanup(&pid_file, "sleep");
    assert!(!still, "the background child survived the deadline");

    let flood = ["/bin/sh", "-c", "yes; sleep 30"];
    assert_eq!(SystemRunner.bounded(&flood, limits), Err(BoundedError::OutputLimit));
    // stdout + stderr count together.
    let both = ["/bin/sh", "-c", "head -c 600 /dev/zero; head -c 600 /dev/zero >&2"];
    assert_eq!(SystemRunner.bounded(&both, limits), Err(BoundedError::OutputLimit));
    assert!(SystemRunner.bounded(&["/bin/sh", "-c", "head -c 1024 /dev/zero"], limits).is_ok());
}

#[test]
fn bounded_classifies_start_failures() {
    assert_eq!(SystemRunner.bounded(&["/nonexistent/binary"], Bounded::AUDIT), Err(BoundedError::Unavailable));
    let dir = Scratch::new("noexec");
    let script = dir.path().join("script");
    fs::write(&script, "#!/bin/sh\n").unwrap();
    assert_eq!(SystemRunner.bounded(&[script.to_str().unwrap()], Bounded::AUDIT), Err(BoundedError::CouldNotExecute));
    assert_eq!(
        SystemRunner.bounded(&[], Bounded::AUDIT).unwrap_err().to_string(),
        "command argv must be a non-empty sequence"
    );
}

// ----------------------------------------------------------------------------------------------
// Capture contract

#[test]
fn the_real_runner_reads_curl_output_beyond_the_core_bound() {
    let output = SystemRunner.capture(
        &["/bin/sh", "-c", "head -c 10000 /dev/zero | tr '\\0' x; echo"],
        1_048_576,
        Capture::VERSION_AGENT,
    );
    assert_eq!(output.trim().len(), 10000);
    assert!(SystemRunner.capture(&["false"], 64, Capture::VERSION_AGENT).starts_with("exit=1"));
    // The Core bound keeps the 4096-character tail.
    let core = SystemRunner.capture(
        &["/bin/sh", "-c", "head -c 10000 /dev/zero | tr '\\0' x; printf END"],
        1_000_000,
        Capture::CORE,
    );
    assert_eq!(core.chars().count(), 4096);
    assert!(core.ends_with("END"));
}

#[test]
fn capture_merges_streams_and_reports_in_band() {
    let out = SystemRunner.capture(&["/bin/sh", "-c", "echo out; echo err >&2; exit 7"], 4096, Capture::CORE);
    assert!(out.starts_with("exit=7 "), "{out}");
    assert!(out.contains("out\n") && out.contains("err\n"));
    assert!(is_in_band_failure(&out));
    let missing = SystemRunner.capture(&["/nonexistent/binary"], 4096, Capture::CORE);
    assert_eq!(missing, "diagnostic unavailable: FileNotFoundError");
    let crlf = SystemRunner.capture(&["/bin/sh", "-c", "printf 'a\\r\\nb\\rc'"], 4096, Capture::CORE);
    assert_eq!(crlf, "a\nb\nc");
    let fast = Capture { max_chars: 4096, timeout: Duration::from_millis(300) };
    let started = Instant::now();
    assert_eq!(
        SystemRunner.capture(&["/bin/sh", "-c", "sleep 30 & wait"], 4096, fast),
        "diagnostic unavailable: TimeoutExpired"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(SystemRunner.capture(&["/bin/sh", "-c", "sleep 30"], 10, fast), "diagnostic");
}

#[test]
fn capture_checked_bounds_and_failures() {
    assert_eq!(
        SystemRunner.capture_checked(&["/bin/sh", "-c", "echo ok; echo hidden >&2"], Duration::from_secs(30)).unwrap(),
        "ok\n"
    );
    assert_eq!(
        SystemRunner.capture_checked(&["/bin/sh", "-c", "exit 1"], Duration::from_secs(30)),
        Err(QueryError::Failed)
    );
    assert_eq!(
        SystemRunner
            .capture_checked(&["/bin/sh", "-c", "head -c 70000 /dev/zero | tr '\\0' x"], Duration::from_secs(30)),
        Err(QueryError::ExceededBound)
    );
    assert_eq!(
        SystemRunner.capture_checked(&["/bin/sh", "-c", "sleep 30"], Duration::from_millis(300)),
        Err(QueryError::Failed)
    );
    assert_eq!(SystemRunner.capture_checked(&["/nonexistent"], Duration::from_secs(1)), Err(QueryError::Failed));
}

#[test]
fn the_process_group_proof_sees_live_members() {
    let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
    // Our own group is alive while we run.
    let own_group = unsafe { libc::getpgrp() };
    let started = Instant::now();
    assert_eq!(
        pc_host::runner::wait_process_group_stopped(own_group),
        Err("command process group did not stop after SIGKILL".to_string())
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
    child.kill().unwrap();
    child.wait().unwrap();
    // A group that does not exist is proven gone at once.
    assert_eq!(pc_host::runner::wait_process_group_stopped(i32::MAX - 7), Ok(()));
}
