"""The mutating Core runner must not return control to rollback with live children."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from installer.adapters.core import CoreError, _DefaultCoreRunner


def _alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("leader_exits", [False, True])
def test_timeout_stops_term_ignoring_child_before_rollback(tmp_path, leader_exits):
    pid_file = tmp_path / "worker.pid"
    rollback = tmp_path / "rollback-started"
    late_write = tmp_path / "mutation-after-rollback"
    child = tmp_path / "worker.py"
    child.write_text("""import os, pathlib, signal, sys, time
pid_file, rollback, late_write, close_stderr = sys.argv[1:]
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if close_stderr == 'yes':
    os.close(2)
pathlib.Path(pid_file).write_text(str(os.getpid()))
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    if pathlib.Path(rollback).exists():
        pathlib.Path(late_write).write_text('unexpected mutation')
        break
    time.sleep(0.01)
""")
    # In one case the child closes stderr and the shell waits for it. In the
    # other the shell exits first and the child keeps the stderr pipe open.
    shell = '"$@" &\n' + ("exit 0\n" if leader_exits else "wait\n")
    pid = None
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            _DefaultCoreRunner(timeout=1).run((
                "/bin/sh", "-c", shell, "test-shell", sys.executable, str(child),
                str(pid_file), str(rollback), str(late_write), "no" if leader_exits else "yes",
            ))
        assert pid_file.exists(), "the isolated worker did not start before the timeout"
        pid = int(pid_file.read_text())
        alive_at_return = _alive(pid)
        rollback.touch()  # The transaction can begin rollback only after run() returns.
        deadline = time.monotonic() + 0.3
        while time.monotonic() < deadline and not late_write.exists():
            time.sleep(0.01)
        assert not alive_at_return, "timed-out runner returned while its child was still running"
        assert not late_write.exists(), "a descendant mutated the host after rollback started"
    finally:
        if pid is None and pid_file.exists():
            pid = int(pid_file.read_text())
        if pid is not None and _alive(pid):
            # Only the PID of this test's exact worker is eligible for cleanup.
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
            if str(child).encode() in command:
                os.kill(pid, signal.SIGKILL)


def test_run_suppresses_stdout_preserves_stderr_stdin_and_env(tmp_path, capfd):
    secret = tmp_path / "private-input"
    secret.write_bytes(b"synthetic-secret")
    result = _DefaultCoreRunner().run((
        sys.executable, "-c",
        "import os,sys; data=sys.stdin.buffer.read(); print(data.decode()); "
        "sys.stderr.write(os.environ['TEST_DIAGNOSTIC']); sys.exit(3)",
    ), stdin_path=secret, env={"TEST_DIAGNOSTIC": "safe diagnostic"})
    assert result.returncode == 3
    assert result.stdout is None
    assert result.stderr == b"safe diagnostic"
    assert not capfd.readouterr().out


def test_timeout_preserves_stderr_without_exposing_stdout(capfd):
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        _DefaultCoreRunner(timeout=1).run((
            sys.executable, "-c",
            "import sys,time; print('synthetic-private-output',flush=True); "
            "sys.stderr.write('safe timeout diagnostic'); sys.stderr.flush(); time.sleep(15)",
        ))
    assert caught.value.stdout is None
    assert caught.value.stderr == b"safe timeout diagnostic"
    assert not capfd.readouterr().out


def test_interrupt_stops_the_process_group(tmp_path, monkeypatch):
    pid_file = tmp_path / "interrupt-worker.pid"
    code = ("import os,pathlib,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "os.close(2); pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(15)")
    original = subprocess.Popen.communicate
    interrupted = False

    def interrupt(process, *args, **kwargs):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pid_file.exists(), "the isolated worker did not start"
            raise KeyboardInterrupt()
        return original(process, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt)
    try:
        with pytest.raises(KeyboardInterrupt):
            _DefaultCoreRunner().run(("/bin/sh", "-c", '"$@" & wait', "test-shell",
                                      sys.executable, "-c", code, str(pid_file)))
        assert not _alive(int(pid_file.read_text()))
    finally:
        if pid_file.exists():
            pid = int(pid_file.read_text())
            if _alive(pid) and str(pid_file).encode() in Path(f"/proc/{pid}/cmdline").read_bytes():
                os.kill(pid, signal.SIGKILL)


def test_timeout_drain_is_bounded_when_a_daemon_escapes_the_group(tmp_path):
    pid_file = tmp_path / "escaped-worker.pid"
    code = ("import os,pathlib,sys,time; "
            "os.setsid(); pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
            "sys.stderr.write('safe escaped diagnostic'); sys.stderr.flush(); time.sleep(15)")
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            _DefaultCoreRunner(timeout=1).run((
                "/bin/sh", "-c", '"$@" & wait', "test-shell", sys.executable, "-c", code, str(pid_file),
            ))
        assert time.monotonic() - started < 4
        assert pid_file.exists(), "the isolated worker did not start"
        assert caught.value.stderr == b"safe escaped diagnostic"
    finally:
        if pid_file.exists():
            pid = int(pid_file.read_text())
            if _alive(pid) and str(pid_file).encode() in Path(f"/proc/{pid}/cmdline").read_bytes():
                os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("priority", [SystemExit, KeyboardInterrupt, None])
@pytest.mark.parametrize("failure", ["delete", "logout", "unlink"])
def test_acceptance_cleanup_preserves_process_stop_and_reports_other_failures(tmp_path, monkeypatch, priority, failure):
    runner = _DefaultCoreRunner()
    users = tmp_path / "users"
    users.write_text("owner=" + "a" * 32 + "\n")
    credential = tmp_path / "bootstrap"
    credential.write_text("synthetic-password")
    probe_calls = 0
    temporary = None
    original_unlink = Path.unlink

    def probe(argv, _label):
        nonlocal probe_calls, temporary
        probe_calls += 1
        if probe_calls == 2:
            temporary = Path(argv[-1])
            if priority is not None:
                raise priority("stop before rollback")

    def request(_opener, _domain, path, *, method="GET", **_kwargs):
        if method == "DELETE":
            if failure == "delete":
                raise CoreError("cleanup failed")
            return {}
        if path == "/api/auth/me":
            return {"username": "owner"}
        if path == "/api/users":
            return {"items": []} if method == "GET" else {"reveal_token": "synthetic"}
        return {"secret": "b" * 32}

    def logout(*_args):
        if failure == "logout":
            raise CoreError("cleanup failed")

    def unlink(path, *args, **kwargs):
        if failure == "unlink" and path == temporary:
            raise CoreError("cleanup failed")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(runner, "_run_checked", probe)
    monkeypatch.setattr(runner, "_login", lambda *_args: (object(), "synthetic-csrf"))
    monkeypatch.setattr(runner, "_json_request", request)
    monkeypatch.setattr(runner, "_logout", logout)
    monkeypatch.setattr(Path, "unlink", unlink)
    try:
        with pytest.raises(priority or CoreError, match="stop before rollback" if priority else "cleanup failed"):
            runner._panel_and_respq(
                panel_domain="panel.example.test", proxy_domain="proxy.example.test", users_file=str(users),
                probe_path="/synthetic/probe", bootstrap_credential_file=str(credential),
                acceptance_name="synthetic", recover_existing=False,
            )
    finally:
        if temporary is not None:
            original_unlink(temporary, missing_ok=True)
