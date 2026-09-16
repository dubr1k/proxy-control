"""The Xray-router container as Compose renders it (v0.5): host loopback only, read-only,
the fixed identity 10006, the three secrets, the panel's read-only socket access — and the
state-directory preparer's ownership contract."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATE_PREPARER = ROOT / "scripts" / "prepare-xray-router-state.sh"
XRAY_SHA256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
GEOIP_SHA256 = "744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354"
GEOSITE_SHA256 = "adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9"


def render_compose(*overlays: str) -> dict:
    env = {
        **os.environ,
        "NAIVE_PUBLIC_HOST": "naive.example.com",
        "MIERU_PUBLIC_HOST": "mieru.example.com",
        "MIERU_MITA_BIN": "/opt/pinned/mita",
        "MIERU_MITA_SHA256": "4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31",
        "MIERU_MITA_GID": "321",
        "MIERU_MANAGER_TOKEN_FILE": "/etc/mieru-manager/token",
        "MTPROXY_DOMAIN": "mt.example.com",
        "MTPROXY_BACKEND_PORT": "8445",
        "MTPROXY_COVER_ROOT": "/tmp",
        "XRAY_ROUTER_XRAY_SHA256": XRAY_SHA256,
        "XRAY_ROUTER_GEOIP_SHA256": GEOIP_SHA256,
        "XRAY_ROUTER_GEOSITE_SHA256": GEOSITE_SHA256,
        "XRAY_ROUTER_BIN_DIR": "/opt/pinned/xray-router",
        "XRAY_ROUTER_STATE_DIR": "/var/lib/xray-router",
    }
    argv = ["docker", "compose"]
    for overlay in ("compose.yaml", *overlays):
        argv += ["-f", overlay]
    result = subprocess.run([*argv, "config", "--format", "json"], cwd=ROOT, env=env, text=True,
                            capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_router_overlay_is_loopback_only_read_only_and_pinned():
    config = render_compose("compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml")
    router = config["services"]["xray-router"]
    assert router["container_name"] == "proxy-control-xray-router"
    assert router["user"] == "10006:10006"
    assert router["network_mode"] == "host" and "ports" not in router
    assert router["read_only"] is True and router["cap_drop"] == ["ALL"] and router["pids_limit"] == 128
    assert router["security_opt"] == ["no-new-privileges:true"]
    assert router["tmpfs"] == ["/tmp:size=8m,mode=1777,uid=10006,gid=10006"]
    mounts = {item["target"]: item for item in router["volumes"]}
    assert mounts["/opt/xray"]["source"] == "/opt/pinned/xray-router" and mounts["/opt/xray"]["read_only"] is True
    assert mounts["/opt/xray"].get("bind", {}) in ({}, {"create_host_path": False})
    assert mounts["/var/lib/xray-router"].get("bind", {}) in ({}, {"create_host_path": False})
    writable = {item["target"] for item in router["volumes"] if not item.get("read_only", False)}
    assert writable == {"/var/lib/xray-router", "/run/xray-router"}
    assert (ROOT / "compose.xray-router.yaml").read_text().count("create_host_path: false") == 2
    env = router["environment"]
    assert env["XRAY_ROUTER_XRAY_SHA256"] == XRAY_SHA256 and env["XRAY_ROUTER_GEOSITE_SHA256"] == GEOSITE_SHA256
    assert env["XRAY_ROUTER_EGRESS_WARP"] == "" and env["XRAY_ROUTER_SOCKET_MODE"] == "660"
    assert {s["source"] for s in router["secrets"]} == {"xray-router-ingress-mieru", "xray-router-ingress-naive",
                                                        "xray-router-manager-token"}
    assert router["healthcheck"]["test"] == ["CMD", "python", "-m", "xray_router_manager.healthcheck"]
    assert config["volumes"]["xray-router-run"]["driver_opts"]["o"] == "uid=10006,gid=10006,mode=0770"
    for name in ("xray-router-manager-token", "xray-router-ingress-naive", "xray-router-ingress-mieru"):
        assert config["secrets"][name]["file"].endswith(f"secrets/{name}")


def test_router_overlay_gives_managers_their_ingress_and_the_panel_its_socket():
    config = render_compose("compose.naive.yaml", "compose.mieru.yaml", "compose.xray-router.yaml")
    naive = config["services"]["naive-manager"]["environment"]
    mieru = config["services"]["mieru-manager"]["environment"]
    # The managers' own overlays carry the router keys with empty defaults; the installer
    # fills .env.naive / .env.mieru and the credential files in the state directories.
    assert naive["NAIVE_EGRESS_ROUTER"] == "" and naive["NAIVE_EGRESS_ROUTER_CREDENTIAL_FILE"] == ""
    assert mieru["MIERU_EGRESS_ROUTER"] == "" and mieru["MIERU_EGRESS_ROUTER_CREDENTIAL_FILE"] == ""
    naive_secrets = {s["source"] for s in config["services"]["naive-manager"].get("secrets", [])}
    assert not {s for s in naive_secrets if s.startswith("xray-router")}
    panel = config["services"]["panel"]
    assert panel["depends_on"]["xray-router"]["condition"] == "service_healthy"
    assert panel["group_add"] == ["10001", "10005", "10006"]
    assert panel["environment"]["PANEL_SUPPLEMENTARY_GROUPS"] == "10001,10005,10006"
    assert panel["environment"]["XRAY_ROUTER_ENABLED"] == "true"
    assert panel["environment"]["XRAY_ROUTER_MANAGER_TOKEN_SOURCE"] == "/run/secrets/xray-router-manager-token"
    assert panel["environment"]["XRAY_ROUTER_MANAGER_SOCKET"] == "/run/xray-router/manager.sock"
    assert "XRAY_ROUTER_MANAGER_TOKEN_FILE" not in panel["environment"]
    socket_mount = next(item for item in panel["volumes"] if item["target"] == "/run/xray-router")
    assert socket_mount["read_only"] is True and socket_mount["source"] == "xray-router-run"
    assert "xray-router-ingress-naive" not in {s["source"] for s in panel["secrets"]}


def test_router_overlay_without_mieru_still_renders():
    config = render_compose("compose.naive.yaml", "compose.xray-router.yaml")
    assert "xray-router" in config["services"] and "mieru-manager" not in config["services"]
    assert config["services"]["panel"]["environment"]["PANEL_SUPPLEMENTARY_GROUPS"] == "10001,10005,10006"


def test_dockerfile_and_entrypoint_use_the_reserved_identity():
    dockerfile = (ROOT / "xray_router_manager" / "Dockerfile").read_text()
    assert "--uid 10006" in dockerfile and "--gid 10006" in dockerfile and "USER 10006:10006" in dockerfile
    assert dockerfile.splitlines()[0] == (ROOT / "mieru_manager" / "Dockerfile").read_text().splitlines()[0]
    entrypoint = (ROOT / "panel" / "entrypoint.sh").read_text()
    assert "10001,10005,10006" in entrypoint and "xray-router-manager-token" in entrypoint


def run_state_preparer(mode: str, state_dir: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(STATE_PREPARER), mode, str(state_dir)], cwd=ROOT, text=True, capture_output=True,
                          check=False)


@pytest.mark.skipif(os.geteuid() != 0, reason="state ownership contract requires root")
def test_prepare_and_verify_state_directory(tmp_path):
    state_dir = tmp_path / "state"
    prepared = run_state_preparer("prepare", state_dir)
    assert prepared.returncode == 0, prepared.stderr
    info = state_dir.stat()
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777) == (10006, 10006, 0o700)
    generations = (state_dir / "generations").stat()
    assert (generations.st_uid, generations.st_gid, generations.st_mode & 0o777) == (10006, 10006, 0o700)
    assert run_state_preparer("verify", state_dir).returncode == 0
    (state_dir / "current.json").write_text("{}")
    verified = run_state_preparer("verify", state_dir)
    assert verified.returncode != 0 and "owner 10006:10006" in verified.stderr
    os.chown(state_dir / "current.json", 10006, 10006)
    (state_dir / "current.json").chmod(0o600)
    assert run_state_preparer("verify", state_dir).returncode == 0
    assert run_state_preparer("prepare", state_dir).returncode != 0  # non-empty


def test_state_preparer_refuses_bad_paths(tmp_path):
    for bad in ("relative/path", "/", f"{tmp_path}//state", f"{tmp_path}/state/"):
        result = run_state_preparer("prepare", bad)
        assert result.returncode != 0, bad
    assert run_state_preparer("bogus", tmp_path / "state").returncode != 0
