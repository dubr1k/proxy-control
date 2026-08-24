from __future__ import annotations

import os
import threading
from pathlib import Path

import httpx
import pytest

from version_agent import host
from version_agent.server import Handler, UnixHTTPServer

_STAT = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\nintr 9\n"
_STAT_LATER = "cpu  200 0 200 1300 100 0 0 0 0 0\ncpu0 1 2 3 4\nintr 9\n"
_MEMINFO = "MemTotal:       4008032 kB\nMemFree:         128000 kB\nMemAvailable:   2909568 kB\nBuffers: 100 kB\n"


class _Proc:
    """Stand in for /proc so the parsers are testable off Linux too."""

    def __init__(self, root: Path, stats: list[str]):
        self.root = root
        self.stats = stats

    def joinpath(self, name: str) -> Path:
        # With no sample queued the file simply does not exist, which is what a
        # kernel that stopped exposing it looks like to the parser.
        if name == "stat" and self.stats:
            target = self.root / "stat"
            target.write_text(self.stats.pop(0), encoding="utf-8")
            return target
        return self.root / name


def test_cpu_utilisation_is_a_delta_between_two_samples(tmp_path, monkeypatch):
    """A single /proc/stat read is a total since boot, not current load."""
    monkeypatch.setattr(host, "_PROC", _Proc(tmp_path, [_STAT, _STAT_LATER]))
    monkeypatch.setattr(host, "_SAMPLE_SECONDS", 0)
    (tmp_path / "loadavg").write_text("0.50 0.40 0.30 1/200 5\n", encoding="utf-8")

    cpu = host._cpu()
    # 200 busy jiffies against 800 elapsed: idle+iowait grew 600, total grew 800.
    assert cpu["used_percent"] == 25.0
    assert cpu["load_average"] == [0.5, 0.4, 0.3]


def test_a_stalled_counter_reports_null_rather_than_a_confident_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "_PROC", _Proc(tmp_path, [_STAT, _STAT]))
    monkeypatch.setattr(host, "_SAMPLE_SECONDS", 0)
    (tmp_path / "loadavg").write_text("0.00 0.00 0.00 1/1 2\n", encoding="utf-8")

    assert host._cpu()["used_percent"] is None


def test_memory_counts_reclaimable_cache_as_available(tmp_path, monkeypatch):
    """MemFree would report a healthy cached server as nearly full."""
    monkeypatch.setattr(host, "_PROC", _Proc(tmp_path, []))
    (tmp_path / "meminfo").write_text(_MEMINFO, encoding="utf-8")

    memory = host._memory()
    assert memory["total_bytes"] == 4008032 * 1024
    assert memory["available_bytes"] == 2909568 * 1024
    assert memory["used_percent"] == 27.4


def test_missing_proc_files_degrade_each_section_independently(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "_PROC", _Proc(tmp_path, []))
    metrics = host.host_metrics()
    assert metrics["cpu"] is None and metrics["memory"] is None
    # statvfs still works, so the disk row must survive a blank /proc.
    assert metrics["disk"]["total_bytes"] > 0


def test_disk_reports_space_an_operator_can_actually_write(tmp_path):
    disk = host._disk(str(tmp_path))
    assert disk["available_bytes"] <= disk["total_bytes"]
    assert 0 <= disk["used_percent"] <= 100


def test_host_endpoint_is_read_only_and_rejects_writes(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(host, "_PROC", _Proc(tmp_path, []))
    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    server.agent = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            body = client.get("/v1/host")
            assert body.status_code == 200
            assert set(body.json()) == {"cpu", "memory", "disk"}
            # The endpoint takes no input, so POST must stay a 404, not a route.
            assert client.post("/v1/host", json={}).status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(not Path("/proc/stat").exists(), reason="Linux /proc only")
def test_real_proc_is_parsed_on_linux():
    metrics = host.host_metrics()
    assert metrics["memory"]["total_bytes"] > 0
    assert 0 <= metrics["cpu"]["used_percent"] <= 100
