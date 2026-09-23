"""The panel updates itself (v0.11): the agent syncs the release tree into the project
directory, backs up the tree and the database, rebuilds and recreates the `panel` service,
verifies `/app/VERSION` and rolls everything back otherwise."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import threading
from pathlib import Path

import pytest

from tests.test_version_agent import PANEL_URL, _agent
from tests.test_version_agent_artifacts import _targz
from version_agent.catalog import CatalogError
from version_agent.service import (
    ConflictError,
    RollbackFailedError,
    RolledBackError,
    UpdateError,
    VersionAgent,
)

OLD_PANEL = "0.10.0-beta.1"
NEW_PANEL = "0.11.0-beta.1"
PANEL_CANDIDATE = {
    "version": NEW_PANEL, "tag": f"v{NEW_PANEL}", "kind": "release", "source": "upstream",
    "url": PANEL_URL, "sha256": "0" * 64, "published_at": "2026-09-21T00:00:00Z",
}
PANEL_EXEC = ["docker", "exec", "proxy-control-panel", "cat", "/app/VERSION"]


def _release_tar(entries: dict[str, bytes | tuple[bytes, int]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, value in entries.items():
            data, mode = value if isinstance(value, tuple) else (value, 0o644)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _panel_archive(*, naive: bytes = b"changed naive\n", agent: bytes = b"new agent\n") -> bytes:
    return _release_tar({
        "proxy-control/VERSION": f"{NEW_PANEL}\n".encode(),
        "proxy-control/panel/app.py": b"new panel\n",
        "proxy-control/panel/static/js/app.js": b"new js\n",
        "proxy-control/compose.yaml": b"new compose\n",
        "proxy-control/scripts/tool.sh": (b"#!/bin/sh\n", 0o755),
        "proxy-control/naive_manager/app.py": naive,
        "proxy-control/mieru_manager/app.py": b"same mieru\n",
        "proxy-control/version_agent/service.py": agent,
        # Never synced: the release tree has no secrets, but the sync set must not even look.
        "proxy-control/secrets/panel-master-key": b"from the archive\n",
        "proxy-control/.env": b"FROM=archive\n",
        "proxy-control/tests/test_x.py": b"not synced\n",
    })


class _PanelHost:
    """A fake host: the compose dir, the agent dir, the panel volume and a runner that
    answers `docker` like the real one would. The container reads the VERSION it was created
    with (a single-file bind mount keeps the inode it saw), so `running` changes on `up` only;
    `container_version` is what an `up` leaves running (the file by default)."""

    def __init__(self, tmp_path: Path, *, container_version: str | None = None, migrate: bool = False):
        self.tmp_path = tmp_path
        self.compose = tmp_path / "compose"
        self.agent_dir = tmp_path / "agent"
        self.volume = tmp_path / "volume"
        self.commands: list[list[str]] = []
        self.container_version = container_version
        self.migrate = migrate
        for name, text in {
            "VERSION": f"{OLD_PANEL}\n", "panel/app.py": "old panel\n", "panel/static/js/app.js": "old js\n",
            "compose.yaml": "old compose\n", "naive_manager/app.py": "old naive\n", "mieru_manager/app.py": "same mieru\n",
            "secrets/panel-master-key": "keep me\n", ".env": "KEEP=1\n", "version-overrides/compose.versions.yaml": "keep\n",
        }.items():
            path = self.compose / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (self.agent_dir / "version_agent").mkdir(parents=True)
        (self.agent_dir / "version_agent" / "service.py").write_text("old agent\n")
        self.volume.mkdir()
        (self.volume / "panel.sqlite3").write_bytes(b"db-old")
        (self.volume / "panel.sqlite3-wal").write_bytes(b"wal-old")
        self.running = f"{OLD_PANEL}\n"

    def run(self, command, *, env=None, cwd=None, timeout=None):
        self.commands.append(list(command))
        if command[:3] == ["docker", "volume", "inspect"]:
            return str(self.volume)
        if command[:2] == ["docker", "compose"] and "up" in command and self.migrate \
                and (self.compose / "VERSION").read_text().strip() == NEW_PANEL:
            # A newer panel migrates the database at start-up; the restored one does not.
            (self.volume / "panel.sqlite3").write_bytes(b"db-migrated")
            (self.volume / "panel.sqlite3-shm").write_bytes(b"shm-new")
        if command[:2] == ["docker", "compose"] and "up" in command:
            self.running = self.container_version or (self.compose / "VERSION").read_text()
        if command == PANEL_EXEC:
            return self.running
        return ""

    def agent(self, payload: bytes, **extra) -> VersionAgent:
        agent = _agent(
            self.tmp_path, compose_dir=self.compose, compose_files=("compose.yaml",),
            agent_dir=self.agent_dir, downloader=lambda url: payload, runner=self.run, synchronous=True, **extra,
        )
        digest = hashlib.sha256(payload).hexdigest()
        agent.check_all = lambda current, *, fetcher, router_enabled: {
            "panel": {"latest": NEW_PANEL, "installable": True, "reason": None,
                      "candidates": [{**PANEL_CANDIDATE, "sha256": digest}]}}
        agent.check_upstream()
        self.commands.clear()
        return agent


def _verbs(commands) -> list[str]:
    verbs = []
    for command in commands:
        if command[:2] == ["docker", "compose"]:
            verbs.append(next(word for word in command[2:] if word in ("build", "stop", "up")))
        elif command[:2] == ["docker", "tag"]:
            verbs.append("tag")
        elif command == PANEL_EXEC:
            verbs.append("exec")
        elif command[0] == "systemd-run":
            verbs.append("systemd-run")
    return verbs


def _mutations(commands) -> list[list[str]]:
    """Everything but the read-only question «which version is running»."""
    return [command for command in commands if command != PANEL_EXEC]


def _state(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "state.json").read_text())["components"]["panel"]


def test_panel_current_is_the_running_container_and_the_state_carries_the_status(tmp_path: Path):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())
    listed = agent.list_versions()["components"]["panel"]
    assert listed["current"] == OLD_PANEL and listed["status"] == "ready"
    assert [e["version"] for e in listed["available"]] == [NEW_PANEL]
    assert listed["available"][0]["kind"] == "release" and listed["available"][0]["source"] == "upstream"
    with pytest.raises(ConflictError):
        agent.update("panel", NEW_PANEL, expected_current="0.9.0-beta.1")
    with pytest.raises(CatalogError, match="not approved"):
        agent.update("panel", "0.12.0-beta.1", expected_current=OLD_PANEL)
    (host.compose / "VERSION").write_text(f"{NEW_PANEL}\n")
    host.running = f"{NEW_PANEL}\n"  # already running: nothing to do
    assert agent.update("panel", NEW_PANEL, expected_current=NEW_PANEL) == {
        "component": "panel", "version": NEW_PANEL, "changed": False}
    assert _mutations(host.commands) == []


def test_a_version_file_ahead_of_the_running_panel_does_not_hide_the_update(tmp_path: Path):
    """Seen live: a project dir kept in sync from a working copy got the next release's files
    (VERSION included) while the container still ran the previous build. The panel showed the
    old version, the agent the new one, and the update button stayed disabled."""
    host = _PanelHost(tmp_path)
    (host.compose / "VERSION").write_text(f"{NEW_PANEL}\n")
    agent = host.agent(_panel_archive())
    listed = agent.list_versions()["components"]["panel"]
    assert listed["current"] == OLD_PANEL
    assert [e["version"] for e in listed["available"]] == [NEW_PANEL]
    result = agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert result["changed"] is True
    assert _state(tmp_path)["previous_version"] == OLD_PANEL
    assert agent.list_versions()["components"]["panel"]["current"] == NEW_PANEL


def test_panel_current_falls_back_to_the_version_file_without_a_container(tmp_path: Path):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())

    def down(command, **kwargs):
        if command == PANEL_EXEC:
            raise RuntimeError("No such container: proxy-control-panel")
        return host.run(command, **kwargs)

    agent.runner = down
    assert agent.list_versions()["components"]["panel"]["current"] == OLD_PANEL
    host.running = ""
    agent.runner = host.run
    assert agent.list_versions()["components"]["panel"]["current"] == OLD_PANEL


def test_panel_update_syncs_the_tree_backs_up_the_db_rebuilds_and_verifies(tmp_path: Path):
    host = _PanelHost(tmp_path, migrate=True)
    agent = host.agent(_panel_archive())
    result = agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert result == {"component": "panel", "version": NEW_PANEL, "changed": True, "async": True}
    # The sync set is replaced, everything else in the project dir is left alone.
    assert (host.compose / "VERSION").read_text() == f"{NEW_PANEL}\n"
    assert (host.compose / "panel/app.py").read_text() == "new panel\n"
    assert (host.compose / "compose.yaml").read_text() == "new compose\n"
    assert (host.compose / "scripts/tool.sh").stat().st_mode & 0o111
    assert (host.compose / "secrets/panel-master-key").read_text() == "keep me\n"
    assert (host.compose / ".env").read_text() == "KEEP=1\n"
    assert (host.compose / "version-overrides/compose.versions.yaml").read_text() == "keep\n"
    assert not (host.compose / "tests").exists()
    # Rollback copies: the previous tree and the previous database.
    backups = tmp_path / "backups"
    assert (backups / "panel.previous/panel/app.py").read_text() == "old panel\n"
    assert (backups / "panel.previous/VERSION").read_text() == f"{OLD_PANEL}\n"
    assert (backups / "panel.previous/version_agent/service.py").read_text() == "old agent\n"
    assert (backups / "panel-db.previous/panel.sqlite3").read_bytes() == b"db-old"
    assert (backups / "panel-db.previous/panel.sqlite3-wal").read_bytes() == b"wal-old"
    assert not (backups / "panel-db.previous/panel.sqlite3-shm").exists()
    # The agent's own code follows the release; its restart is the very last command.
    assert (host.agent_dir / "version_agent/service.py").read_text() == "new agent\n"
    assert _verbs(host.commands) == ["exec", "tag", "build", "stop", "up", "exec", "systemd-run"]
    tag = next(c for c in host.commands if c[:2] == ["docker", "tag"])
    assert tag[2] == "mtproxy-panel:latest" and tag[3].startswith("mtproxy-panel:rollback-")
    build = next(c for c in host.commands if "build" in c)
    assert build[:4] == ["docker", "compose", "--project-name", "mtproxy"] and "--env-file" in build
    assert build[-2:] == ["build", "panel"]
    assert ["docker", "volume", "inspect", "-f", "{{.Mountpoint}}", "mtproxy_panel-data"] in host.commands
    assert host.commands[-1] == ["systemd-run", "--on-active=5", "--unit=proxy-control-version-agent-restart",
                                 "systemctl", "restart", "version-agent"]
    state = _state(tmp_path)
    assert state["version"] == NEW_PANEL and state["status"] == "ready" and state["previous_version"] == OLD_PANEL
    assert state["kind"] == "release" and state["url"] == PANEL_URL and state["pending_rebuild"] == ["naive_manager"]
    listed = agent.list_versions()["components"]["panel"]
    assert listed["current"] == NEW_PANEL and listed["status"] == "ready" and listed["pending_rebuild"] == ["naive_manager"]
    assert not (tmp_path / "staging").exists()


def test_panel_update_without_manager_or_agent_changes_neither_flags_nor_restarts(tmp_path: Path):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive(naive=b"old naive\n", agent=b"old agent\n"))
    agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert _state(tmp_path)["pending_rebuild"] == [] and "systemd-run" not in _verbs(host.commands)


def test_panel_update_rolls_back_files_db_and_image_when_the_container_reports_the_old_version(tmp_path: Path):
    host = _PanelHost(tmp_path, container_version=f"{OLD_PANEL}\n", migrate=True)
    agent = host.agent(_panel_archive())
    with pytest.raises(RolledBackError, match="restored"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert (host.compose / "VERSION").read_text() == f"{OLD_PANEL}\n"
    assert (host.compose / "panel/app.py").read_text() == "old panel\n"
    assert (host.compose / "compose.yaml").read_text() == "old compose\n"
    assert not (host.compose / "scripts").exists()
    assert (host.compose / "secrets/panel-master-key").read_text() == "keep me\n"
    assert (host.agent_dir / "version_agent/service.py").read_text() == "old agent\n"
    assert (host.volume / "panel.sqlite3").read_bytes() == b"db-old"
    assert (host.volume / "panel.sqlite3-wal").read_bytes() == b"wal-old"
    assert not (host.volume / "panel.sqlite3-shm").exists()  # the migrated generation's leftovers are gone
    assert _verbs(host.commands) == ["exec", "tag", "build", "stop", "up", "exec", "tag", "up", "exec"]
    tags = [c for c in host.commands if c[:2] == ["docker", "tag"]]
    assert tags[1][2] == tags[0][3] and tags[1][3] == "mtproxy-panel:latest"
    state = _state(tmp_path)
    assert state["version"] == OLD_PANEL and state["status"] == "ready" and "restored" in state["last_error"]
    listed = agent.list_versions()["components"]["panel"]
    assert listed["current"] == OLD_PANEL and listed["status"] == "ready" and "restored" in listed["last_error"]


def test_panel_rollback_that_does_not_verify_is_reported_and_blocks_further_updates(tmp_path: Path):
    host = _PanelHost(tmp_path, container_version="9.9.9\n")
    agent = host.agent(_panel_archive())
    with pytest.raises(RollbackFailedError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    state = _state(tmp_path)
    assert state["status"] == "rollback_failed" and state["version"] == OLD_PANEL
    assert agent.list_versions()["components"]["panel"]["status"] == "rollback_failed"
    with pytest.raises(RollbackFailedError, match="operator recovery"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)


@pytest.mark.parametrize("bad", [
    _release_tar({"proxy-control/VERSION": b"x\n", "proxy-control/../etc/cron.d/x": b"* * * * * root id\n"}),
    _release_tar({"proxy-control/VERSION": b"x\n", "/etc/passwd": b"root::0:0\n"}),
    _release_tar({"proxy-control/VERSION": b"x\n", "other/VERSION": b"x\n"}),
    _targz({"proxy-control/VERSION": b"x\n"}, symlink="proxy-control/panel/link"),
    b"not a tarball",
])
def test_panel_preflight_refuses_an_unsafe_archive_before_touching_anything(tmp_path: Path, bad: bytes):
    host = _PanelHost(tmp_path)
    agent = host.agent(bad)
    with pytest.raises(UpdateError, match="archive"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert (host.compose / "VERSION").read_text() == f"{OLD_PANEL}\n"
    assert not (tmp_path / "backups").exists() and _mutations(host.commands) == []
    state = _state(tmp_path)
    assert state["status"] == "update_failed" and state["version"] == OLD_PANEL and "archive" in state["last_error"]
    # A refused archive is not a broken generation: the next attempt is allowed.
    agent.downloader = lambda url: _panel_archive()
    with pytest.raises(UpdateError, match="SHA-256"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)


def test_panel_digest_mismatch_touches_nothing(tmp_path: Path):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())
    agent.downloader = lambda url: _panel_archive(agent=b"tampered\n")
    with pytest.raises(UpdateError, match="SHA-256 mismatch"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert (host.compose / "VERSION").read_text() == f"{OLD_PANEL}\n" and _mutations(host.commands) == []


def test_a_second_panel_update_is_refused_while_one_is_running(tmp_path: Path):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())
    state = json.loads((tmp_path / "state.json").read_text())
    state["components"]["panel"] = {"version": OLD_PANEL, "status": "updating"}
    (tmp_path / "state.json").write_text(json.dumps(state))
    assert agent.list_versions()["components"]["panel"]["status"] == "updating"
    with pytest.raises(ConflictError, match="already"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert _mutations(host.commands) == []


def test_panel_update_runs_in_a_background_thread_and_the_request_returns_first(tmp_path: Path):
    host = _PanelHost(tmp_path)
    started = threading.Event()
    release = threading.Event()
    real_run = host.run

    def run(command, **kwargs):
        if command[:2] == ["docker", "tag"]:
            started.set()
            assert release.wait(5)
        return real_run(command, **kwargs)

    agent = host.agent(_panel_archive())
    agent.runner = run
    agent.synchronous = False
    result = agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert result["async"] is True and started.wait(5)
    assert agent.list_versions()["components"]["panel"]["status"] == "updating"
    with pytest.raises(ConflictError, match="already"):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    release.set()
    agent.panel_thread.join(5)
    listed = agent.list_versions()["components"]["panel"]
    assert listed["status"] == "ready" and listed["current"] == NEW_PANEL


def test_panel_worker_swallows_a_failure_in_the_background_and_persists_it(tmp_path: Path):
    host = _PanelHost(tmp_path, container_version="9.9.9\n")
    agent = host.agent(_panel_archive())
    agent.synchronous = False
    agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    agent.panel_thread.join(5)
    assert not agent.panel_thread.is_alive()
    assert _state(tmp_path)["status"] == "rollback_failed"
