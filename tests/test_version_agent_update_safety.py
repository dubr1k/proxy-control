"""Update failure injection: real SQLite WAL and optional MCP release parity."""
import sqlite3

import pytest

from tests.test_version_agent_panel import (
    NEW_PANEL, OLD_PANEL, _PanelHost, _panel_archive, _release_tar, _state,
)
from version_agent.service import RollbackFailedError, RolledBackError, UpdateError, VersionAgent


def test_mcp_source_is_updated_and_reported_for_rebuild(tmp_path):
    host = _PanelHost(tmp_path)
    source = host.compose / "mcp_server/server.py"
    source.parent.mkdir()
    source.write_text("old mcp")
    agent = host.agent(_release_tar({
        "proxy-control/VERSION": NEW_PANEL.encode(),
        "proxy-control/mcp_server/server.py": b"new mcp",
    }))
    agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert source.read_text() == "new mcp"
    assert _state(tmp_path)["pending_rebuild"] == ["mcp_server"]
    assert (tmp_path / "backups/panel.previous/mcp_server/server.py").read_text() == "old mcp"


def test_rollback_quiesces_real_sqlite_writer_and_restores_integrity(tmp_path):
    host = _PanelHost(tmp_path)
    for path in host.volume.iterdir():
        path.unlink()
    database = host.volume / "panel.sqlite3"
    writer = sqlite3.connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE records (value TEXT)")
    writer.execute("INSERT INTO records VALUES ('previous')")
    writer.commit()
    run = host.run
    stops = []

    def runner(command, **kwargs):
        nonlocal writer
        if command[:2] == ["docker", "compose"] and "stop" in command:
            stops.append(command)
            if writer is not None:
                writer.close()
                writer = None
        if command[:2] == ["docker", "ps"]:
            return "writer" if writer is not None else ""
        result = run(command, **kwargs)
        if command[:2] == ["docker", "compose"] and "up" in command:
            if (host.compose / "VERSION").read_text().strip() == NEW_PANEL:
                writer = sqlite3.connect(database)
                writer.execute("INSERT INTO records VALUES ('new generation')")
                writer.commit()
                raise RuntimeError("health check failed with SQLite writer still running")
        return result

    agent = host.agent(_panel_archive())
    agent.compose_files = ("compose.yaml", "compose.fleet-central.yaml")
    agent.runner = runner
    try:
        with pytest.raises(RolledBackError):
            agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
        assert len(stops) == 2 and all(c[-2:] == ["panel", "fleet-ingress"] for c in stops)
        with sqlite3.connect(database) as restored:
            assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert restored.execute("SELECT value FROM records").fetchall() == [("previous",)]
    finally:
        if writer is not None:
            writer.close()


@pytest.mark.parametrize("failure", ["stop", "writer"])
def test_rollback_refuses_to_overwrite_database_if_writers_cannot_be_stopped(tmp_path, failure):
    host = _PanelHost(tmp_path, migrate=True, container_version="unexpected")
    agent = host.agent(_panel_archive())
    run = host.run
    stops = 0

    def runner(command, **kwargs):
        nonlocal stops
        if command[:2] == ["docker", "compose"] and "stop" in command:
            stops += 1
            if stops == 2 and failure == "stop":
                raise RuntimeError("stop failed")
        if command[:2] == ["docker", "ps"] and stops == 2 and failure == "writer":
            return "unexpected writer"
        return run(command, **kwargs)

    agent.runner = runner
    with pytest.raises(RollbackFailedError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert (host.volume / "panel.sqlite3").read_bytes() == b"db-migrated"
    assert (tmp_path / "backups/panel-db.previous/panel.sqlite3").read_bytes() == b"db-old"
    assert _state(tmp_path)["status"] == "rollback_failed"


def test_failed_database_snapshot_never_restores_a_partial_set(tmp_path, monkeypatch):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())
    original = VersionAgent._copy_db_file

    def copy(source, target):
        if target.parent.name == "panel-db.previous" and source.name.endswith("-wal"):
            raise OSError("disk full")
        original(source, target)

    monkeypatch.setattr(VersionAgent, "_copy_db_file", staticmethod(copy))
    with pytest.raises(RolledBackError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert (host.volume / "panel.sqlite3-wal").read_bytes() == b"wal-old"


def test_mcp_source_rolls_back_with_failed_panel_generation(tmp_path):
    host = _PanelHost(tmp_path, container_version=OLD_PANEL)
    source = host.compose / "mcp_server/server.py"
    source.parent.mkdir()
    source.write_text("old mcp")
    agent = host.agent(_release_tar({
        "proxy-control/VERSION": NEW_PANEL.encode(),
        "proxy-control/mcp_server/server.py": b"new mcp",
    }))
    with pytest.raises(RolledBackError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert source.read_text() == "old mcp"


def test_rollback_image_is_the_running_container_even_when_latest_was_rebuilt(tmp_path):
    host = _PanelHost(tmp_path, container_version=OLD_PANEL)
    running_image = "sha256:" + "1" * 64
    run = host.run

    def runner(command, **kwargs):
        if command == ["docker", "inspect", "--format", "{{.Image}}", "proxy-control-panel"]:
            host.commands.append(command)
            return running_image
        return run(command, **kwargs)

    agent = host.agent(_panel_archive())
    agent.runner = runner
    with pytest.raises(RolledBackError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    tags = [command for command in host.commands if command[:2] == ["docker", "tag"]]
    assert tags[0][2] == running_image  # latest may already name a different image
    assert tags[1][2] == tags[0][3] and tags[1][3] == "mtproxy-panel:latest"


@pytest.mark.parametrize("failure", ["identity", "tag"])
def test_missing_rollback_image_refuses_before_recreating_from_latest(tmp_path, failure):
    host = _PanelHost(tmp_path)
    agent = host.agent(_panel_archive())
    run = host.run

    def runner(command, **kwargs):
        if failure == "identity" and command[:4] == ["docker", "inspect", "--format", "{{.Image}}"]:
            return ""
        if failure == "tag" and command[:2] == ["docker", "tag"]:
            raise RuntimeError("could not save rollback image")
        return run(command, **kwargs)

    agent.runner = runner
    with pytest.raises(UpdateError):
        agent.update("panel", NEW_PANEL, expected_current=OLD_PANEL)
    assert not any(command[:2] == ["docker", "compose"] for command in host.commands)
    assert (host.compose / "VERSION").read_text().strip() == OLD_PANEL
