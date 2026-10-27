"""External tests require the real release executables; absence is a setup error."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def installer_binary() -> Path:
    path = Path(os.environ.get("PROXY_CONTROL_TEST_INSTALLER", ROOT / "installer/target/debug/proxy-control-installer"))
    assert path.is_file() and os.access(path, os.X_OK), f"Build the native installer and set PROXY_CONTROL_TEST_INSTALLER: {path}"
    return path.resolve()


@pytest.fixture(scope="session")
def panel_binary() -> Path:
    path = Path(os.environ.get("PROXY_CONTROL_TEST_PANEL", ROOT / "panel/target/debug/panel"))
    assert path.is_file() and os.access(path, os.X_OK), f"Build the native panel and set PROXY_CONTROL_TEST_PANEL: {path}"
    return path.resolve()


@pytest.fixture(scope="session")
def agent_binary() -> Path:
    path = Path(os.environ.get("PROXY_CONTROL_TEST_AGENT", ROOT / "version_agent/target/debug/proxy-control-version-agent"))
    assert path.is_file() and os.access(path, os.X_OK), f"Build the native agent and set PROXY_CONTROL_TEST_AGENT: {path}"
    return path.resolve()
