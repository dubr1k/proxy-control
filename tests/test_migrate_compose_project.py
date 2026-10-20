"""3.0: `scripts/migrate-compose-project.sh` moves an installed stack from the Compose project
`mtproxy` to `proxy_panel_by_dubr1k` — the running images tagged with the new names (no rebuild), the
data volumes copied while the stack is stopped, the same model up under the new name, the old project
back on any failure — against a fake `docker` that records what it was asked."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "migrate-compose-project.sh"
IMAGE = "sha256:" + "b" * 64
pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="the migration runs as root (the lab suite does)")

FAKE = r'''#!/usr/bin/env python3
import json, sys
state_path = sys.argv[0] + ".json"
state = json.load(open(state_path))
args = sys.argv[1:]
line = " ".join(args)
with open(state["log"], "a") as log:
    log.write(line + "\n")
def out(text=""):
    print(text)
    sys.exit(0)
def save():
    json.dump(state, open(state_path, "w"))
if args[:2] == ["ps", "-a"] and "label=com.docker.compose.project=mtproxy" in line:
    out("\n".join(state["legacy"]))
if args[:2] == ["ps", "--filter"] and "label=com.docker.compose.project=mtproxy" in line:
    out("\n".join(state["running"]))
if args[:2] == ["inspect", "--format"] and "config_files" in line:
    out("\n".join(state["files"] for _ in state["legacy"]))
if args[:2] == ["inspect", "--format"] and "environment_file" in line:
    out("\n".join(state["envs"] for _ in state["legacy"]))
if args[:2] == ["inspect", "--format"]:
    out(state["image"])
if args[0] == "compose":
    project = args[args.index("--project-name") + 1]
    if "config" in args:
        out(json.dumps(state["config"]))
    if "ps" in args:
        out("c-" + args[-1])
    if "up" in args and project in state.get("fail_up", []):
        sys.exit(1)
    if "version" in args:
        out("2.40.3")
    out()
if args[:2] == ["volume", "inspect"] and "--format" not in args:
    sys.exit(0 if args[2] in state["volumes"] else 1)
if args[:2] == ["volume", "create"]:
    state["volumes"].append(args[-1]); save(); out(args[-1])
if args[:2] == ["volume", "rm"]:
    if args[-1] in state["volumes"]:
        state["volumes"].remove(args[-1]); save()
    out()
if args[:2] == ["volume", "ls"]:
    out("\n".join(v for v in state["volumes"] if v.startswith("mtproxy_")))
if args[:2] == ["volume", "inspect"]:
    out("tmpfs" if args[-1].endswith("-run") else "")
if args[:2] == ["image", "inspect"]:
    out(state["image"])
out()
'''


@pytest.fixture
def host(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name in ("compose.yaml", "compose.xray-router.yaml", ".env", ".env.xray-router"):
        (project / name).write_text("x: 1\n")
    (project / "version-overrides").mkdir()
    (project / "version-overrides" / "compose.versions.yaml").write_text("x: 1\n")
    agent_env = tmp_path / "version-agent.env"
    agent_env.write_text("PROXY_CONTROL_COMPOSE_DIR=/x\nPROXY_CONTROL_PANEL_IMAGE=mtproxy-panel\n"
                         "PROXY_CONTROL_PANEL_VOLUME=mtproxy_panel-data\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE)
    docker.chmod(0o755)
    state = {
        "log": str(tmp_path / "docker.log"),
        "legacy": ["c1", "c2"],
        "running": ["mask", "panel", "xray-router-ingress"],
        # The overrides first and the router before compose.yaml: the script orders them.
        "files": f"{project}/version-overrides/compose.versions.yaml,{project}/compose.xray-router.yaml,{project}/compose.yaml",
        "envs": f"{project}/.env,{project}/.env.xray-router",
        "image": IMAGE,
        "config": {"services": {"mask": {"image": "caddy"}, "panel": {"build": {"context": "panel"}},
                                "xray-router-ingress": {"build": {"context": "."}}, "naive-manager": {"build": {}}},
                   "volumes": {"panel-data": {}, "telemt-config": {}, "xray-router-run": {"driver_opts": {"type": "tmpfs"}}}},
        "volumes": ["mtproxy_panel-data", "mtproxy_telemt-config", "mtproxy_xray-router-run"],
    }
    (bin_dir / "docker.json").write_text(json.dumps(state))
    return {"tmp": tmp_path, "project": project, "bin": bin_dir, "agent_env": agent_env}


def _state(host) -> dict:
    return json.loads((host["bin"] / "docker.json").read_text())


def _set(host, **changes):
    state = _state(host)
    state.update(changes)
    (host["bin"] / "docker.json").write_text(json.dumps(state))


def _run(host):
    environment = {"PATH": f"{host['bin']}:/usr/bin:/bin", "MIGRATE_AGENT_ENV": str(host["agent_env"])}
    result = subprocess.run(["bash", str(SCRIPT), "--dir", str(host["project"]), "--lang", "en"], env=environment,
                            capture_output=True, text=True, timeout=60)
    log = (host["tmp"] / "docker.log").read_text().splitlines() if (host["tmp"] / "docker.log").exists() else []
    return result, log


def test_moves_the_running_stack_to_the_new_project_and_keeps_the_old_volumes(host):
    result, log = _run(host)
    assert result.returncode == 0, result.stderr
    project = host["project"]
    model = (f"--project-directory {project} --env-file {project}/.env --env-file {project}/.env.xray-router "
             f"-f {project}/compose.yaml -f {project}/compose.xray-router.yaml -f {project}/version-overrides/compose.versions.yaml")
    # The running images keep their bytes under the new names; only built services are tagged.
    assert f"tag {IMAGE} proxy_panel_by_dubr1k-panel:latest" in log
    assert f"tag {IMAGE} proxy_panel_by_dubr1k-xray-router-ingress:latest" in log
    assert not any("naive-manager:latest" in line for line in log)  # not running
    stop = log.index(f"compose --project-name mtproxy {model} stop")
    creates = [i for i, line in enumerate(log) if line.startswith("volume create")]
    copies = [i for i, line in enumerate(log) if line.startswith("run --rm --network none --user 0")]
    down = log.index(f"compose --project-name mtproxy {model} down --remove-orphans")
    up = log.index(f"compose --project-name proxy_panel_by_dubr1k {model} up -d --no-build --wait mask panel xray-router-ingress")
    assert stop < min(creates) and max(copies) < down < up
    assert len(creates) == 2 and all("--label com.docker.compose.project=proxy_panel_by_dubr1k" in log[i] for i in creates)
    assert any("mtproxy_panel-data:/from:ro" in log[i] and "proxy_panel_by_dubr1k_panel-data:/to" in log[i] for i in copies)
    assert not any("xray-router-run:/from" in line for line in log)  # tmpfs sockets are not copied
    volumes = _state(host)["volumes"]
    assert {"mtproxy_panel-data", "mtproxy_telemt-config"} <= set(volumes)  # the way back
    assert "mtproxy_xray-router-run" not in volumes
    assert host["agent_env"].read_text().splitlines()[1:] == [
        "PROXY_CONTROL_PANEL_IMAGE=proxy_panel_by_dubr1k-panel", "PROXY_CONTROL_PANEL_VOLUME=proxy_panel_by_dubr1k_panel-data"]
    assert "the stack runs as proxy_panel_by_dubr1k" in result.stdout


def test_a_moved_host_is_left_alone(host):
    _set(host, legacy=[])
    result, log = _run(host)
    assert result.returncode == 0 and "already runs as proxy_panel_by_dubr1k" in result.stdout
    assert log == ["ps -a -q --filter label=com.docker.compose.project=mtproxy"]


def test_a_failed_start_brings_the_old_project_back_and_drops_the_copies(host):
    _set(host, fail_up=["proxy_panel_by_dubr1k"])
    result, log = _run(host)
    assert result.returncode != 0 and "the mtproxy project is back" in result.stderr
    assert any(line.startswith("compose --project-name proxy_panel_by_dubr1k") and line.endswith("down --remove-orphans") for line in log)
    assert log[-1].startswith("compose --project-name mtproxy") and log[-1].endswith("up -d --no-build --wait mask panel xray-router-ingress")
    volumes = _state(host)["volumes"]
    assert not any(v.startswith("proxy_panel_by_dubr1k_") for v in volumes)
    assert {"mtproxy_panel-data", "mtproxy_telemt-config", "mtproxy_xray-router-run"} <= set(volumes)
    assert "mtproxy-panel" in host["agent_env"].read_text()


def test_a_missing_compose_file_refuses_before_anything_stops(host):
    (host["project"] / "compose.xray-router.yaml").unlink()
    result, log = _run(host)
    assert result.returncode != 0 and "is gone" in result.stderr
    assert not any(" stop" in line or line.startswith("tag ") for line in log)


def test_update_host_runs_the_migration_at_its_end():
    text = (ROOT / "scripts" / "update-host.sh").read_text()
    migrate = text.index('scripts/migrate-compose-project.sh" --dir "$DIR"')
    assert text.index("installer.ingress_upgrade") < migrate < text.index("bad=$(docker ps -a")
