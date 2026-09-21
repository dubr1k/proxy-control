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


PANEL_URL = "https://github.com/dubr1k/proxy-control/releases/download/v0.11.0-beta.1/proxy-control-v0.11.0-beta.1.tar.gz"


def test_catalog_accepts_a_panel_release_entry_and_refuses_it_elsewhere(tmp_path: Path):
    from version_agent.catalog import entry_from_dict

    release = {"version": "0.11.0-beta.1", "kind": "release", "url": PANEL_URL, "sha256": "1" * 64, "source": "upstream"}
    entry = entry_from_dict("panel", release)
    assert entry.kind == "release" and entry.url == PANEL_URL and entry.sha256 == "1" * 64 and entry.source == "upstream"
    assert entry.public() == {"version": "0.11.0-beta.1", "kind": "release", "source": "upstream", "url": PANEL_URL, "sha256": "1" * 64}
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {"panel": [{**release, "source": "catalog"}]}}))
    assert load_catalog(catalog).entry("panel", "0.11.0-beta.1").source == "catalog"
    with pytest.raises(CatalogError, match="HTTPS"):
        entry_from_dict("panel", {**release, "url": "http://github.com/x.tar.gz"})
    with pytest.raises(CatalogError, match="SHA-256"):
        entry_from_dict("panel", {**release, "sha256": "nope"})
    with pytest.raises(CatalogError, match="unknown release field"):
        entry_from_dict("panel", {**release, "archive": {"format": "tar.gz", "member": "VERSION"}})
    with pytest.raises(CatalogError, match="unsupported artifact kind"):
        entry_from_dict("mita", release)
    with pytest.raises(CatalogError, match="unsupported artifact kind"):
        entry_from_dict("panel", {"version": "0.11.0-beta.1", "kind": "binary", "url": PANEL_URL, "sha256": "1" * 64})


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
    assert calls == [{"telemt": None, "naive": None, "mita": None, "panel": None}]
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


XRAY_MEMBERS = ("xray", "geoip.dat", "geosite.dat")
XRAY_STATUS = ["docker", "exec", "proxy-control-xray-router", "python", "-m", "xray_router_manager.healthcheck", "--status"]


def _xray_zip() -> bytes:
    return _zip({"xray": b"xray-new", "geoip.dat": b"geoip", "geosite.dat": b"geosite", "README.md": b"x"})


def _xray_status(version: str, phase: str = "idle") -> str:
    return json.dumps({"xray_version": f"Xray {version} (Xray, Penetrates Everything.) Custom (go1.24 linux/amd64)",
                       "phase": phase, "running": {"generation": 3}}) + "\n"


def _xray_fixture(tmp_path: Path, *, overlay_text: str) -> tuple[Path, Path, Path, bytes]:
    bin_dir = tmp_path / "xray-router"
    bin_dir.mkdir()
    for name in XRAY_MEMBERS:
        (bin_dir / name).write_bytes(b"old-" + name.encode())
    (bin_dir / "xray").chmod(0o755)
    overlay = tmp_path / ".env.xray-router"
    overlay.write_text(overlay_text)
    payload = _xray_zip()
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "components": {"xray": [{
        "version": "26.4.1", "kind": "binary",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v26.4.1/Xray-linux-64.zip",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "archive": {"format": "zip", "members": {"xray": "xray", "geoip.dat": "geoip.dat", "geosite.dat": "geosite.dat"}}}]}}))
    return bin_dir, overlay, catalog, payload


def test_xray_update_replaces_members_rewrites_overlay_and_verifies_the_running_version(tmp_path: Path):
    bin_dir, overlay, catalog, payload = _xray_fixture(tmp_path, overlay_text=(
        "XRAY_ROUTER_BIN_DIR=" + str(tmp_path / "xray-router") + "\nXRAY_ROUTER_XRAY_SHA256=" + "0" * 64
        + "\nXRAY_ROUTER_GEOIP_SHA256=" + "1" * 64 + "\nXRAY_ROUTER_GEOSITE_SHA256=" + "2" * 64 + "\nXRAY_ROUTER_EGRESS_WARP=\n"))
    (tmp_path / ".env").write_text("PANEL_DOMAIN=p.example.com\n")
    commands = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        if command == XRAY_STATUS:
            return _xray_status("26.4.1")
        return ""

    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=tmp_path,
                         compose_files=("compose.yaml", "compose.xray-router.yaml"), router_enabled=True,
                         xray_bin_dir=bin_dir, xray_overlay=overlay, downloader=lambda url: payload, runner=run)

    result = agent.update("xray", "26.4.1", expected_current=None)

    assert result["changed"] is True
    assert (bin_dir / "xray").read_bytes() == b"xray-new" and (bin_dir / "geosite.dat").read_bytes() == b"geosite"
    assert (bin_dir / "xray").stat().st_mode & 0o777 == 0o755 and (bin_dir / "geoip.dat").stat().st_mode & 0o777 == 0o644
    assert not (bin_dir / "README.md").exists()
    text = overlay.read_text()
    assert f"XRAY_ROUTER_XRAY_SHA256={hashlib.sha256(b'xray-new').hexdigest()}" in text
    assert f"XRAY_ROUTER_GEOSITE_SHA256={hashlib.sha256(b'geosite').hexdigest()}" in text
    assert "XRAY_ROUTER_EGRESS_WARP=" in text and "XRAY_ROUTER_BIN_DIR=" in text and "0" * 64 not in text
    [up] = [c for c in commands if c[:4] == ["docker", "compose", "--project-name", "mtproxy"]]
    assert up[-4:] == ["up", "-d", "--wait", "xray-router"]
    assert [up[i + 1] for i, part in enumerate(up) if part == "--env-file"] == [str(tmp_path / ".env"), str(overlay)]
    assert commands.index(up) < commands.index(XRAY_STATUS)
    state = json.loads((tmp_path / "state.json").read_text())["components"]["xray"]
    assert state["members"] == {name: hashlib.sha256(data).hexdigest() for name, data in
                                (("xray", b"xray-new"), ("geoip.dat", b"geoip"), ("geosite.dat", b"geosite"))}
    assert state["version"] == "26.4.1" and state["sha256"] == hashlib.sha256(payload).hexdigest()
    backups = tmp_path / "backups" / "xray.previous"
    assert (backups / "xray").read_bytes() == b"old-xray"
    listed = agent.list_versions()["components"]["xray"]
    assert listed["current"] == "26.4.1"


def test_xray_update_rolls_back_all_three_members_when_the_router_reports_another_version(tmp_path: Path, exdev_between_directories):
    bin_dir, overlay, catalog, payload = _xray_fixture(tmp_path, overlay_text="XRAY_ROUTER_XRAY_SHA256=" + "0" * 64 + "\n")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema": 2, "components": {"xray": {"version": "26.3.27"}}}))
    ups = 0

    def run(command, *, env=None, cwd=None, timeout=None):
        nonlocal ups
        if command[-4:] == ["up", "-d", "--wait", "xray-router"]:
            ups += 1
        if command == XRAY_STATUS:
            # The container keeps reporting the old build: the new one never came up.
            return _xray_status("26.3.27")
        return ""

    agent = VersionAgent(catalog_path=catalog, state_path=state, compose_dir=tmp_path, compose_files=("compose.yaml",),
                         router_enabled=True, xray_bin_dir=bin_dir, xray_overlay=overlay, downloader=lambda url: payload, runner=run)

    with pytest.raises(RolledBackError, match="restored and verified"):
        agent.update("xray", "26.4.1", expected_current="26.3.27")

    assert {n: (bin_dir / n).read_bytes() for n in XRAY_MEMBERS} == {n: b"old-" + n.encode() for n in XRAY_MEMBERS}
    assert (bin_dir / "xray").stat().st_mode & 0o777 == 0o755
    assert overlay.read_text() == "XRAY_ROUTER_XRAY_SHA256=" + "0" * 64 + "\n"
    assert ups == 2
    assert json.loads(state.read_text())["components"]["xray"]["version"] == "26.3.27"


def test_xray_rollback_that_does_not_reach_idle_is_reported_as_unverified(tmp_path: Path):
    bin_dir, overlay, catalog, payload = _xray_fixture(tmp_path, overlay_text="XRAY_ROUTER_XRAY_SHA256=" + "0" * 64 + "\n")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema": 2, "components": {"xray": {"version": "26.3.27"}}}))

    def run(command, *, env=None, cwd=None, timeout=None):
        if command == XRAY_STATUS:
            return _xray_status("26.3.27", phase="broken")
        return ""

    agent = VersionAgent(catalog_path=catalog, state_path=state, compose_dir=tmp_path, compose_files=("compose.yaml",),
                         router_enabled=True, xray_bin_dir=bin_dir, xray_overlay=overlay, downloader=lambda url: payload, runner=run)

    with pytest.raises(RollbackFailedError):
        agent.update("xray", "26.4.1", expected_current="26.3.27")

    saved = json.loads(state.read_text())["components"]["xray"]
    assert saved["version"] == "26.3.27" and saved["status"] == "rollback_failed"


def test_xray_is_refused_without_the_router_and_with_a_mismatched_archive(tmp_path: Path):
    bin_dir, overlay, catalog, payload = _xray_fixture(tmp_path, overlay_text="")
    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=tmp_path,
                         compose_files=("compose.yaml",), router_enabled=False, xray_bin_dir=bin_dir, xray_overlay=overlay,
                         downloader=lambda url: payload, runner=lambda *a, **k: "")
    assert "xray" not in agent.list_versions()["components"]
    with pytest.raises(CatalogError, match="unsupported component"):
        agent.update("xray", "26.4.1", expected_current=None)
    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", compose_dir=tmp_path,
                         compose_files=("compose.yaml",), router_enabled=True, xray_bin_dir=bin_dir, xray_overlay=overlay,
                         downloader=lambda url: payload + b"x", runner=lambda *a, **k: "")
    with pytest.raises(UpdateError, match="SHA-256 mismatch"):
        agent.update("xray", "26.4.1", expected_current=None)
    assert (bin_dir / "xray").read_bytes() == b"old-xray" and overlay.read_text() == ""


def _build_catalog(path: Path) -> None:
    path.write_text(json.dumps({"schema": 1, "components": {"naive": [{"version": "2.12.0", "kind": "build", "build": {
        "caddy_version": "2.12.0", "builder_image": "caddy:2.12.0-builder@sha256:" + "e" * 64,
        "forwardproxy_commit": "d" * 40}}]}}))


def test_naive_build_writes_a_pinned_dockerfile_builds_extracts_and_installs(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    _build_catalog(catalog)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    target.chmod(0o755)
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text(PINNED_CADDY + "\n")
    build_dir = tmp_path / "caddy-build"
    commands = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append((command, env))
        if command[:2] == ["docker", "create"]:
            return "0123456789abcdef\n"
        if command[:2] == ["docker", "cp"]:
            Path(command[3]).write_bytes(BINARY)
            return ""
        if len(command) == 2 and command[1] == "version":
            return "v2.12.0 h1:newbuildhash=\n"
        return "active\n"

    def no_download(url):
        raise AssertionError("no download for a build")

    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", binary_paths={"naive": target},
                         service_names={"naive": "caddy-naive"}, checkers={"naive": "/usr/local/libexec/check-naive-caddy-build"},
                         version_pins={"naive": pin}, caddy_build_dir=build_dir, downloader=no_download, runner=run)

    result = agent.update("naive", "2.12.0", expected_current=None)

    assert result["changed"] is True
    dockerfile = (build_dir / "Dockerfile").read_text()
    assert "FROM caddy:2.12.0-builder@sha256:" + "e" * 64 + " AS builder" in dockerfile
    assert "xcaddy build v2.12.0" in dockerfile and "github.com/klzgrad/forwardproxy@" + "d" * 40 in dockerfile
    assert "COPY --from=builder /usr/bin/caddy /caddy" in dockerfile
    [build] = [c for c, _ in commands if c[:2] == ["docker", "build"]]
    assert build[2:4] == ["-f", str(build_dir / "Dockerfile")] and build[-1] == str(build_dir)
    assert ["docker", "rm", "0123456789abcdef"] in [c for c, _ in commands]
    assert target.read_bytes() == BINARY and pin.read_text().strip() == "v2.12.0 h1:newbuildhash="
    assert any(env and env.get("EXPECTED_CADDY_VERSION") == "v2.12.0 h1:newbuildhash=" for _, env in commands)
    assert ["systemctl", "restart", "caddy-naive"] in [c for c, _ in commands]
    assert not (build_dir / "caddy").exists()
    state = json.loads((tmp_path / "state.json").read_text())["components"]["naive"]
    assert state["version"] == "2.12.0" and state["kind"] == "build" and state["runtime_version"] == "v2.12.0 h1:newbuildhash="
    assert state["sha256"] == BINARY_SHA256 and state["build"]["caddy_version"] == "2.12.0"


def test_naive_build_failure_leaves_the_running_binary_alone(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    _build_catalog(catalog)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")
    pin = tmp_path / "caddy-naive.pin"
    pin.write_text(PINNED_CADDY + "\n")
    commands = []

    def run(command, *, env=None, cwd=None, timeout=None):
        commands.append(command)
        if command[:2] == ["docker", "build"]:
            raise RuntimeError("build failed")
        return "active\n"

    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", binary_paths={"naive": target},
                         service_names={"naive": "caddy-naive"}, version_pins={"naive": pin},
                         caddy_build_dir=tmp_path / "caddy-build", downloader=lambda url: BINARY, runner=run)

    with pytest.raises(UpdateError) as failure:
        agent.update("naive", "2.12.0", expected_current=None)

    assert not isinstance(failure.value, RolledBackError)
    assert target.read_bytes() == b"old" and pin.read_text().strip() == PINNED_CADDY
    assert not any(c[:2] == ["systemctl", "restart"] for c in commands)


def test_naive_build_that_reports_another_caddy_version_is_refused(tmp_path: Path):
    catalog = tmp_path / "catalog.json"
    _build_catalog(catalog)
    target = tmp_path / "caddy"
    target.write_bytes(b"old")

    def run(command, *, env=None, cwd=None, timeout=None):
        if command[:2] == ["docker", "create"]:
            return "0123456789abcdef\n"
        if command[:2] == ["docker", "cp"]:
            Path(command[3]).write_bytes(BINARY)
            return ""
        if len(command) == 2 and command[1] == "version":
            return "v2.11.4 h1:oldbuildhash=\n"
        return "active\n"

    agent = VersionAgent(catalog_path=catalog, state_path=tmp_path / "state.json", binary_paths={"naive": target},
                         service_names={"naive": "caddy-naive"}, caddy_build_dir=tmp_path / "caddy-build",
                         downloader=lambda url: BINARY, runner=run)

    with pytest.raises(UpdateError, match="expected v2.12.0"):
        agent.update("naive", "2.12.0", expected_current=None)
    assert target.read_bytes() == b"old"


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
    (tmp_path / ".optional.env").write_text("NAIVE_EGRESS_WARP=socks5://127.0.0.1:45000\n")
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
    # `.optional.env` (a host keeps its WARP egress there) rides right after `.env`.
    assert env_files == [str(tmp_path / ".env"), str(tmp_path / ".optional.env"), str(tmp_path / ".env.naive"), str(overlay)]
    assert "-f" in up and str(tmp_path / "compose.mieru.yaml") in up
    assert "version-overrides" not in " ".join(up)
    assert commands.index(["systemctl", "restart", "mita"]) < commands.index(up)


@pytest.fixture
def exdev_between_directories(monkeypatch):
    """Under the unit's `ProtectSystem=strict` every `ReadWritePaths` entry is its own bind
    mount: a rename from the state directory into `/usr/…` fails with EXDEV. Simulate it
    for every rename that crosses directories."""
    import errno
    import os as os_module
    real = os_module.replace

    def replace(src, dst, *args, **kwargs):
        if Path(src).parent != Path(dst).parent:
            raise OSError(errno.EXDEV, "Invalid cross-device link", str(src), 0, str(dst))
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr("version_agent.service.os.replace", replace)


def test_mita_update_restores_the_consumer_pin_when_the_manager_does_not_come_back(tmp_path: Path, exdev_between_directories):
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog)
    target = tmp_path / "bin" / "mita"
    target.parent.mkdir()
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

    assert target.read_bytes() == b"old" and target.stat().st_mode & 0o777 == 0o755
    assert not (target.parent / ".mita.proxy-control-restore").exists()
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
    # The overlays' variables are required by the model: every Compose call names them.
    for command in commands:
        if command[:2] == ["docker", "compose"]:
            assert [command[i + 1] for i, part in enumerate(command) if part == "--env-file"] == [str(compose_dir / ".env")], command
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
