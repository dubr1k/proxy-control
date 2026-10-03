import importlib.util
import json
import hashlib
import socket
import uuid
import urllib.request
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/lab/managed-xui-clients.py"
spec = importlib.util.spec_from_file_location("managed_xui_clients", SCRIPT)
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


def test_preflight_refuses_missing_or_unpinned_real_clients(tmp_path):
    manifest = {"xray": {"path": str(tmp_path / "xray"), "sha256": "a" * 64},
                "hysteria": {"path": str(tmp_path / "hy"), "sha256": "b" * 64},
                "cases": {}}
    with pytest.raises(probe.ProbeError, match="missing executable"):
        probe.preflight(manifest, tmp_path)
    binary = tmp_path / "xray"
    binary.write_bytes(b"x")
    binary.chmod(0o700)
    with pytest.raises(probe.ProbeError, match="digest mismatch"):
        probe.preflight(manifest, tmp_path)
    manifest["xray"]["sha256"] = None
    with pytest.raises(probe.ProbeError, match="digest mismatch"):
        probe.preflight(manifest, tmp_path)
    with pytest.raises(probe.ProbeError, match="invalid manifest"):
        probe.preflight([], tmp_path)


def _valid_manifest(tmp_path):
    binaries = {}
    for name in ("xray", "hysteria"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        path.chmod(0o700)
        binaries[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    manifest = {**binaries, "cases": {}}
    for name, port in zip(probe.CASES, range(18080, 18083)):
        if name == "hysteria2":
            config = {"server": "hy2.lab.test:443", "auth": "valid-secret",
                      "tls": {"sni": "hy2.lab.test"}, "socks5": {"listen": f"127.0.0.1:{port}"}}
            credential = "auth"
        else:
            valid_id = str(uuid.uuid4())
            config = {"inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks"}],
                      "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address":
                          "vless.lab.test" if name == "vless-tcp" else "xhttp.lab.test", "port": 443,
                          "users": [{"id": valid_id}]}]}, "streamSettings": {"network":
                          "tcp" if name == "vless-tcp" else "xhttp", "security": "reality",
                          "realitySettings": {"serverName": "vless.lab.test" if name == "vless-tcp" else "xhttp.lab.test"}}}]}
            credential = "outbounds.0.settings.vnext.0.users.0.id"
        bad = json.loads(json.dumps(config))
        cursor = bad
        parts = credential.split(".")
        for part in parts[:-1]:
            cursor = cursor[int(part)] if part.isdigit() else cursor[part]
        cursor[parts[-1]] = "invalid-secret" if name == "hysteria2" else str(uuid.uuid4())
        for variant, value in (("positive", config), ("negative", bad)):
            path = tmp_path / f"{name}-{variant}.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        manifest["cases"][name] = {"positive": f"{name}-positive.json", "negative": f"{name}-negative.json",
                                    "socks_port": port, "credential_path": credential}
    return manifest


def test_preflight_requires_all_positive_negative_configs_and_distinct_ports(tmp_path):
    manifest = _valid_manifest(tmp_path)
    saved = manifest["cases"].pop("xhttp")
    with pytest.raises(probe.ProbeError, match="missing case"):
        probe.preflight(manifest, tmp_path)
    manifest["cases"]["xhttp"] = saved
    probe.preflight(manifest, tmp_path)
    manifest["cases"]["xhttp"]["socks_port"] = 18080
    with pytest.raises(probe.ProbeError, match="duplicate SOCKS"):
        probe.preflight(manifest, tmp_path)
    assert "password" not in json.dumps(probe.empty_report())


def test_preflight_refuses_unrelated_route_or_noncredential_change(tmp_path):
    manifest = _valid_manifest(tmp_path)
    for variant in ("positive", "negative"):
        path = tmp_path / f"xhttp-{variant}.json"
        config = json.loads(path.read_text())
        config["outbounds"][0]["settings"]["vnext"][0]["address"] = "other.lab.test"
        path.write_text(json.dumps(config))
        path.chmod(0o600)
    with pytest.raises(probe.ProbeError, match="target mismatch"):
        probe.preflight(manifest, tmp_path)
    manifest = _valid_manifest(tmp_path)
    path = tmp_path / "vless-tcp-negative.json"
    config = json.loads(path.read_text())
    config["outbounds"].append({"protocol": "freedom"})
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    with pytest.raises(probe.ProbeError, match="credential-only"):
        probe.preflight(manifest, tmp_path)


def test_preflight_requires_root_private_manifest_and_configs(tmp_path):
    manifest = _valid_manifest(tmp_path)
    path = tmp_path / "hysteria2-positive.json"
    path.chmod(0o644)
    with pytest.raises(probe.ProbeError, match="root-private"):
        probe.preflight(manifest, tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o644)
    with pytest.raises(probe.ProbeError, match="root-private"):
        probe.read_manifest(manifest_path)


def test_stale_socks_port_is_rejected_and_client_failure_is_not_denial():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with pytest.raises(probe.ProbeError, match="SOCKS port already in use"):
            probe.assert_port_free(listener.getsockname()[1])


def test_cleanup_signals_process_group_even_if_leader_exited(monkeypatch):
    signals = []
    def kill_group(pid, sig):
        if sig == 0:
            raise ProcessLookupError
        signals.append((pid, sig))
    monkeypatch.setattr(probe.os, "killpg", kill_group)
    class Exited:
        pid = 12345
        def poll(self):
            return 1
        def wait(self, timeout):
            return 1
    probe.cleanup_group(Exited())
    assert signals and signals[0][0] == 12345


def test_differential_requires_two_payloads_and_no_negative_echo():
    good = probe.Transfer(returncode=0, payload_echo=True)
    denied = probe.Transfer(returncode=7, payload_echo=False)
    result = probe.classify_case(good, denied, good, (0, 1, 1, 2))
    assert result == {"positive_payload_before": True, "negative_attempt": "transfer_failed_no_echo",
                      "positive_payload_after": True, "controlled_differential_denial": True}
    assert probe.classify_case(good, denied, good, (0, 1, 2, 3))["controlled_differential_denial"] is False
    assert probe.classify_case(good, denied, denied, (0, 1, 1, 1))["controlled_differential_denial"] is False


def test_vless_wrong_credential_must_remain_valid_uuid(tmp_path):
    manifest = _valid_manifest(tmp_path)
    path = tmp_path / "vless-tcp-negative.json"
    bad = json.loads(path.read_text())
    bad["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = "not-a-uuid"
    path.write_text(json.dumps(bad))
    path.chmod(0o600)
    with pytest.raises(probe.ProbeError, match="invalid VLESS UUID"):
        probe.preflight(manifest, tmp_path)


def test_run_reports_per_case_differential_without_credentials(tmp_path, monkeypatch):
    manifest = _valid_manifest(tmp_path)
    def transfer(_binary, config, _port, target, *, hysteria):
        if "negative" in config.name:
            return probe.Transfer(7, False)
        with urllib.request.urlopen(urllib.request.Request(target, data=probe.PAYLOAD), timeout=2) as response:
            assert response.read() == probe.PAYLOAD
        return probe.Transfer(0, True)
    monkeypatch.setattr(probe, "one_probe", transfer)
    report = probe.run(manifest, tmp_path)
    assert report["pass"] is True
    assert all(item["controlled_differential_denial"] for item in report["cases"].values())
    assert "valid-secret" not in json.dumps(report)
