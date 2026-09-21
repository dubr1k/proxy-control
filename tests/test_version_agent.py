from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.test_version_agent_artifacts import _targz, _zip
from version_agent.catalog import CatalogError, load_catalog
from version_agent.service import (
    ConflictError,
    RollbackFailedError,
    RolledBackError,
    UpdateError,
    VersionAgent,
)


TELEMT_IMAGE = "ghcr.io/example/telemt@sha256:" + "a" * 64
BINARY = b"verified-runtime-binary\n"
BINARY_SHA256 = hashlib.sha256(BINARY).hexdigest()
PINNED_CADDY = "v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0="


def write_catalog(path: Path, *, naive_runtime_version: str | None = None) -> None:
    naive = {
        "version": "2.11.4-custom.1",
        "kind": "binary",
        "url": "https://artifacts.example.com/caddy-2.11.4-custom.1",
        "sha256": BINARY_SHA256,
    }
    if naive_runtime_version:
        naive["runtime_version"] = naive_runtime_version
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [
                        {"version": "3.4.25", "kind": "image", "image": TELEMT_IMAGE}
                    ],
                    "naive": [naive],
                    "mita": [
                        {
                            "version": "3.35.0",
                            "kind": "binary",
                            "url": "https://artifacts.example.com/mita-3.35.0",
                            "sha256": BINARY_SHA256,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def test_catalog_requires_immutable_artifacts(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [
                        {"version": "latest", "kind": "image", "image": "ghcr.io/example/telemt:latest"}
                    ],
                    "naive": [],
                    "mita": [],
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="immutable image"):
        load_catalog(catalog)


def test_catalog_accepts_archive_members_and_the_xray_component(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {
        "xray": [{"version": "26.4.1", "kind": "binary",
                  "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip",
                  "sha256": "a" * 64,
                  "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}}],
        "mita": [{"version": "3.37.0", "kind": "binary",
                  "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz",
                  "sha256": "b" * 64, "archive": {"format": "tar.gz", "member": "mita"}}]}}))
    loaded = load_catalog(catalog)
    entry = loaded.entry("xray", "26.4.1")
    assert entry.archive["members"]["geosite.dat"] == "geosite.dat" and entry.source == "catalog"
    assert loaded.entry("mita", "3.37.0").public()["archive"] == {"format": "tar.gz", "member": "mita"}
    assert loaded.entry("mita", "3.37.0").public()["source"] == "catalog"


def test_catalog_rejects_archive_members_that_escape(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {"mita": [{
        "version": "3.37.0", "kind": "binary", "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/x.tar.gz",
        "sha256": "b" * 64, "archive": {"format": "tar.gz", "member": "../mita"}}]}}))
    with pytest.raises(CatalogError, match="archive member"):
        load_catalog(catalog)


def test_catalog_requires_the_xray_member_set_and_a_single_member_elsewhere(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {"xray": [{
        "version": "26.4.1", "kind": "binary", "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/x.zip",
        "sha256": "a" * 64, "archive": {"format": "zip", "member": "xray"}}]}}))
    with pytest.raises(CatalogError, match="members"):
        load_catalog(catalog)
    catalog.write_text(json.dumps({"schema": 1, "components": {"naive": [{
        "version": "2.12.0", "kind": "binary", "url": "https://example.com/caddy",
        "sha256": "a" * 64, "source": "somewhere"}]}}))
    with pytest.raises(CatalogError, match="source"):
        load_catalog(catalog)


def test_catalog_accepts_a_caddy_build_entry(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {"naive": [{
        "version": "2.12.0", "kind": "build",
        "build": {"caddy_version": "2.12.0", "builder_image": "caddy:2.12.0-builder@sha256:" + "c" * 64,
                  "forwardproxy_commit": "d" * 40}}]}}))
    entry = load_catalog(catalog).entry("naive", "2.12.0")
    assert entry.kind == "build" and entry.build["caddy_version"] == "2.12.0"
    assert entry.public()["build"]["forwardproxy_commit"] == "d" * 40
    catalog.write_text(json.dumps({"schema": 1, "components": {"mita": [{
        "version": "2.12.0", "kind": "build",
        "build": {"caddy_version": "2.12.0", "builder_image": "caddy:2.12.0-builder@sha256:" + "c" * 64,
                  "forwardproxy_commit": "d" * 40}}]}}))
    with pytest.raises(CatalogError, match="unsupported artifact kind"):
        load_catalog(catalog)


def _agent(tmp_path, **extra):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    extra.setdefault("runner", lambda command, *, env=None, cwd=None, timeout=None: "active\n")
    return VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", **extra)


MITA_CANDIDATE = {
    "version": "3.37.0", "tag": "v3.37.0", "kind": "binary", "source": "upstream",
    "url": "https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz",
    "sha256": "b" * 64, "archive": {"format": "tar.gz", "member": "mita"}, "published_at": None,
}


def test_check_upstream_caches_candidates_and_lists_them_after_the_catalog(tmp_path: Path):
    calls = []

    def fake_check_all(current, *, fetcher, router_enabled):
        calls.append(dict(current))
        return {
            "mita": {"latest": "3.37.0", "installable": True, "reason": None, "candidates": [dict(MITA_CANDIDATE)]},
            "telemt": {"latest": None, "installable": False, "reason": "no_releases", "candidates": []},
            "naive": {"latest": None, "installable": False, "reason": None, "candidates": [], "last_error": "upstream unreachable"},
            "xray": {"latest": None, "installable": False, "reason": "router_not_installed", "candidates": []},
        }

    now = [1_000_000]
    agent = _agent(tmp_path, clock=lambda: now[0])
    agent.check_all = fake_check_all
    listed = agent.check_upstream()
    assert calls == [{"telemt": None, "naive": None, "mita": None}]
    mita = listed["components"]["mita"]
    assert [e["version"] for e in mita["available"]] == ["3.35.0", "3.37.0"]
    assert mita["available"][0]["source"] == "catalog" and mita["available"][1]["source"] == "upstream"
    assert mita["upstream"] == {"checked_at": 1_000_000, "latest": "3.37.0", "installable": True, "reason": None, "last_error": None}
    assert listed["checked_at"] == 1_000_000 and listed["upstream_enabled"] is True
    assert listed["components"]["naive"]["upstream"]["last_error"] == "upstream unreachable"
    assert "xray" not in listed["components"]  # router off → the component is not shown
    assert json.loads((tmp_path / "state.json").read_text())["schema"] == 2
    assert agent.list_versions() == listed
    now[0] += 30
    agent.check_upstream()
    assert len(calls) == 1  # inside the 60 s window the cache answers
    now[0] += 31
    agent.check_upstream()
    assert len(calls) == 2


def test_a_failed_source_keeps_its_previous_candidates_next_to_the_error(tmp_path: Path):
    answers = [
        {"mita": {"latest": "3.37.0", "installable": True, "reason": None, "candidates": [dict(MITA_CANDIDATE)]}},
        {"mita": {"latest": None, "installable": False, "reason": None, "candidates": [], "last_error": "upstream answered 403"}},
    ]
    now = [1_000]
    agent = _agent(tmp_path, clock=lambda: now[0])
    agent.check_all = lambda current, *, fetcher, router_enabled: answers.pop(0)
    agent.check_upstream()
    now[0] += 100
    listed = agent.check_upstream()
    mita = listed["components"]["mita"]
    assert [e["version"] for e in mita["available"]] == ["3.35.0", "3.37.0"]
    assert mita["upstream"]["last_error"] == "upstream answered 403" and mita["upstream"]["latest"] == "3.37.0"


def test_update_installs_a_cached_upstream_candidate_by_version(tmp_path: Path):
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    payload = _targz({"mita": BINARY})
    digest = hashlib.sha256(payload).hexdigest()
    commands = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        return "active\n"

    agent = _agent(tmp_path, binary_paths={"mita": target}, service_names={"mita": "mita"},
                   downloader=lambda url: payload, runner=run)
    agent.check_all = lambda current, *, fetcher, router_enabled: {
        "mita": {"latest": "3.37.0", "installable": True, "reason": None,
                 "candidates": [{**MITA_CANDIDATE, "sha256": digest}]}}
    agent.check_upstream()
    result = agent.update("mita", "3.37.0", expected_current=None)
    assert result["changed"] is True and target.read_bytes() == BINARY
    state = json.loads((tmp_path / "state.json").read_text())["components"]["mita"]
    assert state["version"] == "3.37.0" and state["source"] == "upstream"
    assert state["sha256"] == hashlib.sha256(BINARY).hexdigest()
    assert state["archive"] == {"format": "tar.gz", "member": "mita"}
    assert ["systemctl", "restart", "mita"] in commands


def test_update_refuses_a_version_that_is_neither_in_the_catalog_nor_cached(tmp_path: Path):
    agent = _agent(tmp_path, binary_paths={"mita": tmp_path / "mita"}, service_names={"mita": "mita"})
    with pytest.raises(CatalogError, match="not approved"):
        agent.update("mita", "9.9.9", expected_current=None)
    with pytest.raises(CatalogError, match="unsupported component"):
        agent.update("xray", "26.4.1", expected_current=None)


def test_archive_member_hash_is_checked_against_the_archive_not_the_file(tmp_path: Path):
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    payload = _targz({"mita": BINARY})
    agent = _agent(tmp_path, binary_paths={"mita": target}, service_names={"mita": "mita"},
                   downloader=lambda url: payload)
    agent.check_all = lambda current, *, fetcher, router_enabled: {
        "mita": {"latest": "3.37.0", "installable": True, "reason": None,
                 "candidates": [{**MITA_CANDIDATE, "sha256": BINARY_SHA256}]}}
    agent.check_upstream()
    with pytest.raises(UpdateError, match="SHA-256 mismatch"):
        agent.update("mita", "3.37.0", expected_current=None)
    assert target.read_bytes() == b"old"


def test_upstream_disabled_lists_only_the_catalog_and_refuses_to_check(tmp_path: Path):
    agent = _agent(tmp_path, upstream_enabled=False)
    listed = agent.list_versions()
    assert listed["upstream_enabled"] is False
    assert [e["version"] for e in listed["components"]["mita"]["available"]] == ["3.35.0"]
    with pytest.raises(UpdateError, match="disabled"):
        agent.check_upstream()


def test_catalog_rejects_non_https_binary_sources(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "schema": 1,
                "components": {
                    "telemt": [],
                    "naive": [
                        {
                            "version": "2.11.4",
                            "kind": "binary",
                            "url": "http://artifacts.example.com/caddy",
                            "sha256": "b" * 64,
                        }
                    ],
                    "mita": [],
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CatalogError, match="HTTPS"):
        load_catalog(catalog)


def test_binary_update_uses_catalog_hash_and_persists_revision(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    state = tmp_path / "state.json"
    commands: list[tuple[list[str], dict | None]] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append((command, env))
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        checkers={"naive": "/usr/local/libexec/check-naive-caddy-build"},
        downloader=lambda url: BINARY,
        runner=run,
    )

    result = agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert result["version"] == "2.11.4-custom.1"
    assert target.read_bytes() == BINARY
    assert target.stat().st_mode & 0o111
    assert json.loads(state.read_text())["components"]["naive"]["version"] == "2.11.4-custom.1"
    # A reload keeps the running process on the old binary, so replacing it restarts.
    assert any(command == ["systemctl", "restart", "caddy-naive"] for command, _ in commands)
    assert not any(command[:2] == ["systemctl", "reload"] for command, _ in commands)
    assert any(env and str(env.get("CADDY_BIN", "")).endswith(".proxy-control-new") for _, env in commands)


def test_binary_update_records_the_pin_the_unit_check_reads(tmp_path: Path):
    """ExecStartPre runs without the agent's environment: the pin must persist."""
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, naive_runtime_version=PINNED_CADDY)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text("v2.11.3 h1:stale=\n")

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=tmp_path / "state.json",
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        version_pins={"naive": pin},
        downloader=lambda url: BINARY,
        runner=lambda command, *, env=None, cwd=None, timeout=None: "active\n",
    )

    agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert pin.read_text().strip() == PINNED_CADDY


def test_binary_update_restores_the_previous_pin_when_the_service_fails(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, naive_runtime_version=PINNED_CADDY)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text("v2.11.3 h1:previous=\n")
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(":443 {}\n")
    checker = "/usr/local/libexec/check-naive-caddy-build"
    calls: list[tuple[list[str], dict | None]] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        calls.append((command, env))
        if command[:2] == ["systemctl", "restart"] and target.read_bytes() == BINARY:
            raise RuntimeError("restart failed")
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=tmp_path / "state.json",
        binary_paths={"naive": target},
        service_names={"naive": "caddy-naive"},
        version_pins={"naive": pin},
        checkers={"naive": checker},
        caddyfiles={"naive": caddyfile},
        downloader=lambda url: BINARY,
        runner=run,
    )

    with pytest.raises(RolledBackError, match="restored and verified"):
        agent.update("naive", "2.11.4-custom.1", expected_current=None)

    assert target.read_bytes() == b"old"
    assert pin.read_text().strip() == "v2.11.3 h1:previous="
    checker_calls = [env for command, env in calls if command == [checker]]
    assert [env["EXPECTED_CADDY_VERSION"] for env in checker_calls] == [
        PINNED_CADDY,
        "v2.11.3 h1:previous=",
    ]
    assert any(
        command[0] == str(target) and "adapt" in command
        for command, _env in calls
    )


def test_mita_update_rewrites_the_consumer_pin_restarts_slots_and_recreates_the_manager(tmp_path: Path):
    """The manager pins the host binary by digest: its overlay follows the new build."""
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    (tmp_path / "compose.yaml").write_text("services: {}\n")
    (tmp_path / ".env").write_text("PANEL_DOMAIN=p.example.com\n")
    (tmp_path / ".env.naive").write_text("NAIVE_PUBLIC_HOST=n.example.com\n")
    overlay = tmp_path / ".env.mieru"
    overlay.write_text(
        "MIERU_PUBLIC_HOST=m.example.com\nMIERU_MITA_SHA256=" + "0" * 64
        + "\nMIERU_LANE_SLOTS=1:46101:/run/mita1/s:/var/lib/mita1\n"
    )
    commands = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        if command[:3] == ["systemctl", "list-units", "--plain"]:
            return "mita@1.service loaded active running\n"
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=tmp_path,
        compose_files=("compose.yaml", "compose.mieru.yaml"),
        binary_paths={"mita": target}, service_names={"mita": "mita"},
        consumer_overlays={"mita": (overlay, "MIERU_MITA_SHA256", "mieru-manager")},
        downloader=lambda url: BINARY, runner=run,
    )

    agent.update("mita", "3.35.0", expected_current=None)

    text = overlay.read_text()
    assert f"MIERU_MITA_SHA256={BINARY_SHA256}" in text and "MIERU_PUBLIC_HOST=m.example.com" in text
    assert text.index("MIERU_PUBLIC_HOST") < text.index("MIERU_MITA_SHA256") < text.index("MIERU_LANE_SLOTS")
    assert "0" * 64 not in text
    assert ["systemctl", "restart", "mita"] in commands and ["systemctl", "restart", "mita@1"] in commands
    assert ["systemctl", "is-active", "mita@1"] in commands
    [up] = [c for c in commands if c[:4] == ["docker", "compose", "--project-name", "mtproxy"]]
    assert up[-4:] == ["up", "-d", "--wait", "mieru-manager"]
    env_files = [up[i + 1] for i, part in enumerate(up) if part == "--env-file"]
    assert env_files == [str(tmp_path / ".env"), str(tmp_path / ".env.naive"), str(overlay)]
    assert "-f" in up and str(tmp_path / "compose.mieru.yaml") in up
    assert "version-overrides" not in " ".join(up)
    assert commands.index(["systemctl", "restart", "mita"]) < commands.index(up)


def test_mita_update_restores_the_consumer_pin_when_the_manager_does_not_come_back(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    overlay = tmp_path / ".env.mieru"
    overlay.write_text("MIERU_MITA_SHA256=" + "0" * 64 + "\n")
    ups = []

    def run(command, *, env=None, cwd=None, timeout=None):
        if command[-4:-1] == ["up", "-d", "--wait"]:
            ups.append(overlay.read_text())
            if len(ups) == 1:
                raise RuntimeError("unhealthy")
        return "" if command[:3] == ["systemctl", "list-units", "--plain"] else "active\n"

    agent = VersionAgent(
        catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=tmp_path,
        compose_files=("compose.yaml",),
        binary_paths={"mita": target}, service_names={"mita": "mita"},
        consumer_overlays={"mita": (overlay, "MIERU_MITA_SHA256", "mieru-manager")},
        downloader=lambda url: BINARY, runner=run,
    )

    with pytest.raises(RolledBackError):
        agent.update("mita", "3.35.0", expected_current=None)

    assert target.read_bytes() == b"old"
    assert overlay.read_text() == "MIERU_MITA_SHA256=" + "0" * 64 + "\n"
    assert ups == [f"MIERU_MITA_SHA256={BINARY_SHA256}\n", "MIERU_MITA_SHA256=" + "0" * 64 + "\n"]
    assert agent.list_versions()["components"]["mita"]["current"] is None


def test_binary_update_rolls_back_when_service_restart_fails(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"mita": {"version": "3.34.0"}}}))
    calls: list[list[str]] = []
    restart_attempts = 0

    def run(command, *, env=None, cwd=None, timeout=None):
        nonlocal restart_attempts
        calls.append(command)
        if command == ["systemctl", "restart", "mita"]:
            restart_attempts += 1
            if restart_attempts == 1:
                raise RuntimeError("service failed")
        return "active\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"mita": target},
        service_names={"mita": "mita"},
        downloader=lambda url: BINARY,
        runner=run,
    )

    with pytest.raises(RolledBackError, match="restored and verified"):
        agent.update("mita", "3.35.0", expected_current="3.34.0")

    assert target.read_bytes() == b"old"
    assert json.loads(state.read_text())["components"]["mita"]["version"] == "3.34.0"
    assert calls.count(["systemctl", "restart", "mita"]) >= 2


def test_binary_rollback_restart_is_not_success_without_health(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "mita"
    target.write_bytes(b"old")
    target.chmod(0o755)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"mita": {"version": "3.34.0"}}}))
    calls: list[list[str]] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        calls.append(command)
        if command == ["systemctl", "is-active", "mita"]:
            raise RuntimeError("service remained unhealthy")
        return "ok\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"mita": target},
        service_names={"mita": "mita"},
        downloader=lambda url: BINARY,
        runner=run,
    )

    with pytest.raises(RollbackFailedError, match="could not be verified"):
        agent.update("mita", "3.35.0", expected_current="3.34.0")

    saved = json.loads(state.read_text())["components"]["mita"]
    assert target.read_bytes() == b"old"
    assert saved["version"] == "3.34.0"
    assert saved["status"] == "rollback_failed"
    assert agent.list_versions()["components"]["mita"]["status"] == "rollback_failed"
    assert calls.count(["systemctl", "restart", "mita"]) == 2
    assert calls.count(["systemctl", "is-active", "mita"]) == 2

    with pytest.raises(RollbackFailedError, match="operator recovery"):
        agent.update("mita", "3.35.0", expected_current="3.34.0")


def test_update_rejects_stale_expected_revision(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"naive": {"version": "2.11.3"}}}))

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        binary_paths={"naive": tmp_path / "caddy"},
        downloader=lambda url: BINARY,
        runner=lambda *args, **kwargs: "active\n",
    )

    with pytest.raises(ConflictError, match="changed"):
        agent.update("naive", "2.11.4-custom.1", expected_current="2.11.2")


def test_telemt_update_persists_override_and_uses_expected_compose_files(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"telemt": {"version": "3.4.24"}}}))
    compose_dir = tmp_path / "deployment"
    compose_dir.mkdir()
    (compose_dir / "compose.yaml").write_text("name: mtproxy\nservices: {}\n", encoding="utf-8")
    commands: list[list[str]] = []

    old_image = "ghcr.io/example/telemt@sha256:" + "b" * 64

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        if "{{.Config.Image}}" in command:
            override = compose_dir / "version-overrides" / "compose.versions.yaml"
            if override.exists() and TELEMT_IMAGE in override.read_text(encoding="utf-8"):
                return TELEMT_IMAGE
            return old_image
        if "{{.State.Health.Status}}" in command:
            return "healthy\n"
        return "ok\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        compose_dir=compose_dir,
        compose_files=("compose.yaml",),
        telemt_container="telemt-test",
        downloader=lambda url: BINARY,
        runner=run,
    )

    result = agent.update("telemt", "3.4.25", expected_current="3.4.24")

    assert result["version"] == "3.4.25"
    override = compose_dir / "version-overrides" / "compose.versions.yaml"
    assert TELEMT_IMAGE in override.read_text(encoding="utf-8")
    assert any("pull" in command for command in commands)
    assert any("up" in command and "mtproxy" in command for command in commands)
    assert any(command[:2] == ["docker", "inspect"] for command in commands)
    inspect_commands = [command for command in commands if command[:2] == ["docker", "inspect"]]
    assert inspect_commands and inspect_commands[-1][-1] == "telemt-test"


def test_telemt_rollback_verifies_restored_image_and_health(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"components": {"telemt": {"version": "3.4.24"}}}))
    compose_dir = tmp_path / "deployment"
    compose_dir.mkdir()
    (compose_dir / "compose.yaml").write_text("name: mtproxy\nservices: {}\n", encoding="utf-8")
    override = compose_dir / "version-overrides" / "compose.versions.yaml"
    override.parent.mkdir()
    old_image = "ghcr.io/example/telemt@sha256:" + "b" * 64
    old_override = f"services:\n  mtproxy:\n    image: {old_image}\n"
    override.write_text(old_override, encoding="utf-8")
    running_image = old_image
    health_reads: list[str] = []

    def run(command, *, env=None, cwd=None, timeout=None):
        nonlocal running_image
        if command[:3] == ["docker", "compose", "--project-name"] and "up" in command:
            configured = override.read_text(encoding="utf-8") if override.exists() else ""
            running_image = TELEMT_IMAGE if TELEMT_IMAGE in configured else old_image
            return "ok\n"
        if "{{.Config.Image}}" in command:
            return running_image
        if "{{.State.Health.Status}}" in command:
            health_reads.append(running_image)
            return "unhealthy" if running_image == TELEMT_IMAGE else "healthy"
        return "ok\n"

    agent = VersionAgent(
        catalog_path=catalog,
        state_path=state,
        compose_dir=compose_dir,
        compose_files=("compose.yaml",),
        telemt_container="telemt-test",
        runner=run,
        health_timeout=0,
    )

    with pytest.raises(RolledBackError, match="restored and verified"):
        agent.update("telemt", "3.4.25", expected_current="3.4.24")

    assert override.read_text(encoding="utf-8") == old_override
    assert health_reads == [TELEMT_IMAGE, old_image]
    assert json.loads(state.read_text())["components"]["telemt"]["version"] == "3.4.24"
