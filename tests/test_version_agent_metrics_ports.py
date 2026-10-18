from __future__ import annotations

import json
import logging

import pytest

from version_agent import metrics_ports
from version_agent.metrics_ports import discover_ports, load_override, read_env_file

NOFILE = "/nonexistent/override.json"


@pytest.fixture(autouse=True)
def _reset_warnings():
    metrics_ports._warned.clear()


def _discover(tmp_path, files, **kw):
    kw.setdefault("override_path", tmp_path / "override.json")
    kw.setdefault("mita_config", tmp_path / "server_config.json")
    return discover_ports(tmp_path, files, **kw)


def test_core_only_has_mtproxy_default(tmp_path):
    assert _discover(tmp_path, ["compose.yaml"]) == {"mtproxy": {"tcp": [8445], "udp": []}}


def test_mtproxy_backend_port_from_env(tmp_path):
    (tmp_path / ".env").write_text("MTPROXY_BACKEND_PORT=18445\n")
    assert _discover(tmp_path, ["compose.yaml"])["mtproxy"]["tcp"] == [18445]


def test_naive_and_trusttunnel_only_with_their_overlay(tmp_path):
    (tmp_path / ".env.trusttunnel").write_text("TT_LISTEN=127.0.0.1:4460\n")
    both = _discover(tmp_path, ["compose.yaml", "compose.naive.yaml", "compose.trusttunnel.yaml"])
    assert both["naive"] == {"tcp": [4443], "udp": []}
    assert both["trusttunnel"] == {"tcp": [4460], "udp": []}
    plain = _discover(tmp_path, ["compose.yaml"])
    assert "naive" not in plain and "trusttunnel" not in plain


def test_trusttunnel_default_port_without_env(tmp_path):
    assert _discover(tmp_path, ["compose.trusttunnel.yaml"])["trusttunnel"]["tcp"] == [4453]


def test_mieru_ports_from_mita_config_and_lane_slots(tmp_path):
    (tmp_path / "server_config.json").write_text(json.dumps({"portBindings": [
        {"port": 8443, "protocol": "TCP"}, {"portRange": "9000-9002", "protocol": "UDP"},
        {"port": 8443, "protocol": "TCP"},
    ]}))
    (tmp_path / ".env.mieru").write_text("MIERU_LANE_SLOTS=1:46101:/s:/t,2:46102:/s:/t\n")
    mieru = _discover(tmp_path, ["compose.yaml", "compose.mieru.yaml"])["mieru"]
    assert mieru == {"tcp": [8443, 46101, 46102], "udp": [9000, 9001, 9002]}


def test_mieru_without_readable_config_is_omitted(tmp_path):
    assert "mieru" not in _discover(tmp_path, ["compose.mieru.yaml"])


def test_override_replaces_and_adds(tmp_path):
    (tmp_path / "override.json").write_text('{"naive":{"tcp":[4444]},"mieru":{"udp":[5000]}}')
    found = _discover(tmp_path, ["compose.yaml", "compose.naive.yaml"])
    assert found["naive"] == {"tcp": [4444], "udp": []}
    assert found["mieru"] == {"tcp": [], "udp": [5000]}


@pytest.mark.parametrize("payload", [
    "not json", "[]", '{"nope":{"tcp":[1]}}', '{"naive":{"tcp":[0]}}', '{"naive":{"tcp":[70000]}}',
    '{"naive":{"sctp":[1]}}', '{"naive":{"tcp":["80"]}}', '{"naive":{"tcp":[true]}}', '{"naive":[]}',
])
def test_malformed_override_is_ignored_with_one_log_line(tmp_path, caplog, payload):
    path = tmp_path / "override.json"
    path.write_text(payload)
    with caplog.at_level(logging.WARNING, logger="version_agent.metrics"):
        assert load_override(path) == {}
        assert load_override(path) == {}
    assert len([r for r in caplog.records if "override" in r.getMessage()]) == 1


def test_missing_override_is_silent(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="version_agent.metrics"):
        assert load_override(tmp_path / "none.json") == {}
    assert not caplog.records


def test_port_budget_per_protocol(tmp_path):
    (tmp_path / "server_config.json").write_text(json.dumps(
        {"portBindings": [{"portRange": "1000-5000", "protocol": "TCP"}]}))
    mieru = _discover(tmp_path, ["compose.mieru.yaml"])["mieru"]
    assert len(mieru["tcp"]) == metrics_ports.MAX_PORTS_PER_PROTOCOL


def test_read_env_file_strips_quotes_and_comments(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# c\nA=1\nB='two'\nC=\"3\"\nbroken\n")
    assert read_env_file(path) == {"A": "1", "B": "two", "C": "3"}
    assert read_env_file(tmp_path / "missing") == {}


def test_env_reader_is_injectable(tmp_path):
    reader = lambda path: {"TT_LISTEN": "[::1]:4999"} if path.name == ".env.trusttunnel" else {}  # noqa: E731
    found = _discover(tmp_path, ["compose.trusttunnel.yaml"], env_reader=reader)
    assert found["trusttunnel"]["tcp"] == [4999]
