"""`installer/runtime_state.py` (v0.11): the installer accepts the artifact the version-agent
installed after its pin, and nothing else."""
from __future__ import annotations

import json
from pathlib import Path

from installer.runtime_state import accepted_caddy_pins, accepted_sha256, agent_component


def _state(root: Path, components: dict) -> None:
    path = root / "var/lib/proxy-control/version-agent/state.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema": 2, "components": components}))


def test_missing_or_failed_state_yields_only_the_pin(tmp_path: Path):
    assert agent_component(tmp_path, "xray") is None
    assert accepted_sha256(tmp_path, "xray", "xray", "p" * 64) == {"p" * 64}
    _state(tmp_path, {"mita": {"version": "3.37.0", "sha256": "a" * 64, "status": "rollback_failed"}})
    assert accepted_sha256(tmp_path, "mita", None, "p" * 64) == {"p" * 64}


def test_invalid_state_yields_only_the_pin(tmp_path: Path):
    path = tmp_path / "var/lib/proxy-control/version-agent/state.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    assert agent_component(tmp_path, "xray") is None
    path.write_text(json.dumps(["list"]))
    assert agent_component(tmp_path, "xray") is None
    path.write_text(json.dumps({"components": {"xray": {"members": {"xray": "short"}}, "naive": {"runtime_version": ""}}}))
    assert accepted_sha256(tmp_path, "xray", "xray", "p" * 64) == {"p" * 64}
    assert accepted_caddy_pins(tmp_path, "v2.11.4 h1:old=") == {"v2.11.4 h1:old="}


def test_state_adds_the_agent_installed_hashes(tmp_path: Path):
    _state(tmp_path, {"xray": {"version": "26.4.1", "members": {"xray": "x" * 64, "geoip.dat": "g" * 64, "geosite.dat": "s" * 64}},
                      "mita": {"version": "3.37.0", "sha256": "m" * 64},
                      "naive": {"version": "2.12.0", "runtime_version": "v2.12.0 h1:abc="}})
    assert accepted_sha256(tmp_path, "xray", "geoip.dat", "p" * 64) == {"p" * 64, "g" * 64}
    assert accepted_sha256(tmp_path, "mita", None, "p" * 64) == {"p" * 64, "m" * 64}
    assert accepted_caddy_pins(tmp_path, "v2.11.4 h1:old=") == {"v2.11.4 h1:old=", "v2.12.0 h1:abc="}
