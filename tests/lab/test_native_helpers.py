"""External lab-controller behavior, not production Python imports or source wording."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts/lab" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_xray_lab_cache_checks_archive_and_each_member(tmp_path, monkeypatch):
    spike = load("xray-spike")
    tree, cache, work = (tmp_path / name for name in ("tree", "cache", "work"))
    (tree / "release").mkdir(parents=True)
    cache.mkdir()
    work.mkdir()
    archive = cache / "fixture.zip"
    contents = {"xray": b"lab executable", "geoip.dat": b"lab geoip", "geosite.dat": b"lab geosite"}
    with zipfile.ZipFile(archive, "w") as package:
        for name, data in contents.items():
            package.writestr(name, data)
        package.writestr("../unreviewed", "must never extract")
    pin = {"url": "https://fixture.invalid/fixture.zip", "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
           "members": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "mode": "0755" if name == "xray" else "0644"}
                       for name, data in contents.items()}}
    manifest = {"artifacts": [{"name": "xray", "version": "fixture", "platforms": {"amd64": pin}}]}
    manifest_path = tree / "release/external-artifacts.json"
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(spike, "ROOT", tree)
    destination, evidence = spike.stage_xray(cache, work)
    assert {path.name for path in destination.iterdir()} == set(contents)
    assert all((destination / name).read_bytes() == value for name, value in contents.items())
    assert evidence["archive_sha256"] == pin["sha256"]
    assert not (work / "unreviewed").exists()
    pin["members"]["geoip.dat"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    bad = tmp_path / "bad"
    bad.mkdir()
    with pytest.raises(spike.Spike, match="member digest mismatch"):
        spike.stage_xray(cache, bad)


def test_monitoring_queries_mounted_database_read_only(tmp_path, monkeypatch):
    monitoring = load("monitoring-live-check")
    volume = tmp_path / "panel-volume"
    volume.mkdir()
    with sqlite3.connect(volume / "panel.sqlite3") as db:
        db.execute("CREATE TABLE metric_rollups (resolution INTEGER)")
        db.execute("INSERT INTO metric_rollups VALUES (60)")
    container = {"Config": {"Env": ["PANEL_DATABASE=/data/panel.sqlite3"]},
                 "Mounts": [{"Source": str(volume), "Destination": "/data"}]}
    monkeypatch.setattr(monitoring, "sh", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps([container]), ""))
    assert monitoring.panel_db("SELECT count(*) FROM metric_rollups WHERE resolution=60") == [(1,)]
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        monitoring.panel_db("DELETE FROM metric_rollups")


def test_awg_remote_cleanup_uses_native_admin_http(tmp_path):
    from scripts.lab.ui_protocol_dialog_check import isolated_panel

    remote = load("awg-remote-check")
    import httpx

    with isolated_panel(tmp_path) as fixture:
        fixture.api("/api/admins", "POST", {"username": "awgremote", "password": "external-controller-fixture-password", "role": "owner"})
        with httpx.Client(base_url=fixture.base, timeout=10, trust_env=False) as http:
            csrf = http.get("/login").cookies["panel_csrf"]
            response = http.post("/api/auth/login", json={"username": "awgremote", "password": "external-controller-fixture-password"}, headers={"X-CSRF-Token": csrf})
            assert response.status_code in (200, 204)
            http.headers["Cookie"] = f"panel_csrf={http.cookies['panel_csrf']}; panel_session={http.cookies['panel_session']}"
            remote.drop_admin(http)
        assert not any(admin["username"] == "awgremote" for admin in fixture.api("/api/admins")["items"])


def test_fork_probe_requests_actual_native_subscription(tmp_path, monkeypatch):
    from scripts.lab import ui_protocol_dialog_check as dialogs
    from urllib.parse import urlsplit

    import httpx

    probe = load("trusttunnel-fork-core-check")
    monkeypatch.setattr(dialogs, "SUBSCRIPTION_URL", "https://central.example")
    monkeypatch.setattr(dialogs, "SUBSCRIPTION_HOST", "central.example")
    with dialogs.isolated_panel(tmp_path) as fixture:
        cid = fixture.client_id
        started = fixture.api(f"/api/clients/{cid}/grants", "POST", {"grants": [
            {"protocol": "trusttunnel", "node_id": "local", "runtime_username": "tt-fork-check", "options": {}},
        ]})
        dialogs.require(started["status"] == "succeeded", "native TrustTunnel grant failed")
        subscription = fixture.api(f"/api/clients/{cid}/subscription", "POST")
        revealed = fixture.api(f"/api/reveal/{subscription['reveal_token']}")
        with httpx.Client(base_url=fixture.base, headers={"Host": "central.example"}, trust_env=False, timeout=10) as public:
            path = urlsplit(revealed["url"]).path
            for agent, client, expected in (("Throne/1.1.4", None, "throne"), ("sing-box 1.13.0", "hiddify", "hiddify")):
                chosen, body = probe.feed(public, path, agent, client)
                dialogs.require(chosen == expected and [row["type"] for row in body["outbounds"]] == ["trusttunnel"], "native fork feed negotiation failed")
                config = probe.config_of(body)
                dialogs.require(config["route"]["final"] == body["outbounds"][0]["tag"], "fork core config routes through native TrustTunnel feed")
            _, official = probe.feed(public, path, "sing-box 1.13.0")
            dialogs.require(official["outbounds"] == [] and official["proxy_control"]["unsupported"][0]["protocol"] == "trusttunnel", "official agent must not receive fork-only outbound")
