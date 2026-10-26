"""Public installer commands through the real native process, never Python services."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests/fixtures/host-golden"


def invoke(binary: Path, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(binary), "--root", str(root), *arguments], capture_output=True, text=True, timeout=20)


@pytest.mark.parametrize("command", ["status", "resume", "repair", "uninstall"])
def test_missing_journal_refuses_without_creating_transaction(installer_binary, tmp_path, command):
    result = invoke(installer_binary, tmp_path, command)
    assert result.returncode == 2
    assert not result.stdout
    assert not (tmp_path / "var/lib/proxy-control/installer/state.json").exists()


@pytest.mark.parametrize("journal", ["rolled-back", "uninstalled"])
def test_status_reads_historical_journal_without_mutation(installer_binary, tmp_path, journal):
    source = GOLDEN / "journals" / journal / "state.json"
    destination = tmp_path / "var/lib/proxy-control/installer/state.json"
    destination.parent.mkdir(parents=True)
    before = source.read_bytes()
    destination.write_bytes(before)
    result = invoke(installer_binary, tmp_path, "status", "--json")
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    original = json.loads(before)
    assert status["status"] == original["status"]
    assert status["plan_digest"] == original["plan_digest"]
    assert "legacy" not in status
    assert destination.read_bytes() == before


@pytest.mark.parametrize("digest", ["0" * 64, "a" * 12, "A" * 64])
def test_panel_recovery_rejects_unapproved_archive_before_mutation(installer_binary, tmp_path, digest):
    archive = tmp_path / "unapproved.tar.gz"
    archive.write_bytes(b"not an approved release")
    result = invoke(installer_binary, tmp_path, "reconcile-panel-update", "--archive", str(archive), "--sha256", digest)
    assert result.returncode == 2
    assert not result.stdout
    assert archive.read_bytes() == b"not an approved release"
    assert not (tmp_path / "var/lib/proxy-control/installer/state.json").exists()


def test_invalid_config_refuses_before_audit_or_install(installer_binary, tmp_path):
    config = tmp_path / "bad.toml"
    config.write_text('schema = 1\npassword = "must-not-be-accepted"\n')
    result = invoke(installer_binary, tmp_path, "install", "--config", str(config), "--accept-plan", "0" * 64)
    assert result.returncode == 2
    assert not result.stdout
    assert not (tmp_path / "var/lib/proxy-control/installer/state.json").exists()


def test_verify_release_checks_artifact_bytes(installer_binary, tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    payload = release / "payload.tar.gz"
    payload.write_bytes(b"release archive bytes")
    manifest = json.loads((ROOT / "release/external-artifacts.json").read_text())
    manifest["artifacts"][0]["platforms"]["amd64"]["sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
    manifest_path = release / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    arguments = ("verify-release", "artifact", str(manifest_path), "mieru", "amd64", str(payload))
    result = invoke(installer_binary, tmp_path / "host", *arguments)
    assert result.returncode == 0, result.stderr
    payload.write_bytes(b"tampered")
    result = invoke(installer_binary, tmp_path / "host", *arguments)
    assert result.returncode != 0


def test_awg_ports_match_machine_identity_derivation_and_avoid_busy_port(installer_binary, tmp_path):
    identity = "0123456789abcdef0123456789abcdef"
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/machine-id").write_text(identity + "\n")

    def derive(version, attempt):
        return 10240 + int.from_bytes(hashlib.sha256(f"{identity}:{version}:{attempt}".encode()).digest(), "big") % 21761

    command = [str(installer_binary), "awg-ports", "--root", str(tmp_path)]
    first = subprocess.run([*command, "", "--", "1.5", "2.0", "3.1"], capture_output=True, text=True, timeout=10)
    assert first.returncode == 0, first.stderr
    got = dict(item.split("=") for item in first.stdout.split())
    assert got == {version: str(derive(version, 0)) for version in ("1.5", "2.0", "3.1")}
    busy = subprocess.run([*command, got["1.5"], "--", "1.5"], capture_output=True, text=True, timeout=10)
    assert busy.returncode == 0, busy.stderr
    assert dict(item.split("=") for item in busy.stdout.split())["1.5"] == str(derive("1.5", 1))


def test_release_pin_cli_returns_reviewed_manifest_and_refuses_unknown_architecture(installer_binary, tmp_path):
    manifest = ROOT / "release/external-artifacts.json"
    entry = next(item for item in json.loads(manifest.read_text())["artifacts"] if item["name"] == "trusttunnel")
    arguments = ("release-pin", "--manifest", str(manifest), "trusttunnel")
    result = subprocess.run([str(installer_binary), *arguments, "amd64"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f'{entry["version"]} {entry["platforms"]["amd64"]["sha256"]}\n'
    refused = subprocess.run([str(installer_binary), *arguments, "arm64"], capture_output=True, text=True, timeout=10)
    assert refused.returncode == 2
    assert refused.stdout == ""
