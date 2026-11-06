"""Naive client live semantics in the actual monitoring UI, using only synthetic data."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

import test_monitoring_layout as layout
from test_monitoring_layout import CHECK, _eval, _open

browser = layout.browser

ROOT = Path(__file__).resolve().parents[2]


def test_naive_fleet_and_history_behavior_in_node():
    node = shutil.which("node")
    assert node, "Node is required for UI behavior checks"
    result = subprocess.run(
        [node, str(Path(__file__).with_name("naive_monitoring_contract.mjs"))],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.fixture(scope="module")
def stub():
    spec = importlib.util.spec_from_file_location("naive_live_stub", ROOT / "scripts/dev/monitoring-stub-server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = module.node_snapshot

    def snapshot(node, now):
        data = original(node, now)
        if node == "local":
            data["protocols"]["naive"] = {
                "available": True, "live": True, "source": "naive_connect",
                "semantics": "authenticated_connect_payload", "up_bps": 1024,
                "down_bps": 2048, "connections": 3,
            }
        elif node == "fra-1":
            data["protocols"]["naive"].update(live=True, source="kernel", up_bps=999999, down_bps=999999)
        else:
            data["protocols"]["naive"] = {"available": False, "reason": "live_meter_unavailable"}
        return data

    module.node_snapshot = snapshot
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.mark.parametrize(("width", "height"), [(390, 844), (1440, 900)])
def test_naive_client_and_mixed_fleet_cards(stub, browser, width, height):
    report = _open(browser, stub, "now", width, height)
    assert report["problems"] == [] and report["errors"] == [] and report["csp"] == [], report
    def card():
        return _eval(browser, "document.querySelector('[data-proto=naive]').innerText")

    assert "Клиентский трафик · CONNECT" in card()
    assert "Активных туннелей 3" in card()
    _eval(browser, "document.querySelector('[data-mon-node]').value='all';document.querySelector('[data-mon-node]').dispatchEvent(new Event('change',{bubbles:true}));0")
    deadline = time.monotonic() + 10
    while "Покрытие: 1/3" not in card() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert "Покрытие: 1/3" in card(), card()
    assert "Активных туннелей 3" in card()
    assert "МБ/с" not in card(), "legacy port traffic entered the CONNECT card"
    report = json.loads(_eval(browser, CHECK))
    assert report["problems"] == [] and report["errors"] == [] and report["csp"] == [], report
    _eval(browser, "document.querySelector('[data-mon-node]').value='fra-1';document.querySelector('[data-mon-node]').dispatchEvent(new Event('change',{bubbles:true}));0")
    deadline = time.monotonic() + 10
    while "Данные клиентского трафика недоступны" not in card() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert "Данные клиентского трафика недоступны" in card()
    assert "Активных туннелей —" in card()
