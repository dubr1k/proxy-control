"""Native privileged secret CLI and entrypoint fail-before-staging boundaries."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def stage(panel_binary, source, destination):
    return subprocess.run([str(panel_binary), "stage-secret", "stage", str(source), str(destination)], text=True, capture_output=True, timeout=10)


def test_stage_secret_stages_real_file_with_private_metadata(panel_binary, tmp_path):
    assert os.geteuid() == 0, "Run numeric ownership integration tests as root on ams-test"
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"m" * 32)
    source.chmod(0o440)
    os.chown(source, 0, 10005)
    result = stage(panel_binary, source, destination)
    assert result.returncode == 0, result.stderr
    info = destination.stat()
    assert destination.read_bytes() == b"m" * 32
    assert (info.st_uid, info.st_gid, info.st_mode & 0o777, info.st_nlink) == (10001, 101, 0o400, 1)
    destination_before = destination.read_bytes()
    refused = stage(panel_binary, source, destination)
    assert refused.returncode != 0
    assert destination.read_bytes() == destination_before


@pytest.mark.parametrize("defect", ["owner", "group", "mode", "short", "large", "hardlink", "symlink", "missing"])
def test_stage_secret_rejects_invalid_source_without_creating_destination(panel_binary, tmp_path, defect):
    assert os.geteuid() == 0, "Run numeric ownership integration tests as root on ams-test"
    source = tmp_path / "source"
    source.write_bytes(b"m" * (514 if defect == "large" else 31 if defect == "short" else 32))
    source.chmod(0o600 if defect == "mode" else 0o440)
    os.chown(source, 10003 if defect == "owner" else 0, 0 if defect == "group" else 10005)
    if defect == "hardlink":
        (tmp_path / "alias").hardlink_to(source)
    elif defect == "symlink":
        target = source
        source = tmp_path / "source-link"
        source.symlink_to(target)
    elif defect == "missing":
        source.unlink()
    destination = tmp_path / "destination"
    result = stage(panel_binary, source, destination)
    assert result.returncode != 0
    assert not destination.exists()


@pytest.mark.parametrize("value", ["0", "10003", "10005,10005", "10005,10004", "10004", " 10005", "10005 ", "10005,", ",10005", "root", "+10005", "010005"])
def test_panel_entrypoint_rejects_malformed_groups_before_launch(tmp_path, value):
    # Invalid groups are rejected before even resolving the privileged native binary.
    result = subprocess.run(["/bin/sh", str(ROOT / "panel/entrypoint.sh")], env={"PATH": "/usr/bin:/bin", "PANEL_SUPPLEMENTARY_GROUPS": value, "PANEL_RUNTIME_DIR": str(tmp_path)}, text=True, capture_output=True, timeout=10)
    assert result.returncode == 64
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("enabled,groups,master,trust", [
    (False, "", False, False),
    (True, "10005", False, False),
    (True, "10001,10005", True, False),
    (False, "10008", False, True),
    (True, "10001,10005,10008", True, True),
])
def test_entrypoint_stages_native_secrets_and_drops_privileges_in_private_namespace(
    panel_binary, tmp_path, enabled, groups, master, trust,
):
    assert os.geteuid() == 0, "Run entrypoint namespaces as root on ams-test"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # Only installation/user lookup and the final daemon launch are harnessed.
    # Secret verification/copy executes the unmodified real Rust panel.
    install = bin_dir / "install"
    install.write_text(
        "#!/usr/bin/python3\nimport os,sys\n"
        "args=sys.argv[1:]\n"
        "for i in range(1,len(args)):\n"
        " if args[i]=='panel' and args[i-1] in ('-o','-g'): args[i]='10001' if args[i-1]=='-o' else '101'\n"
        "os.execv('/usr/bin/install',['install',*args])\n"
    )
    launch = bin_dir / "setpriv"
    launch.write_text(
        "#!/usr/bin/python3\nimport json,os,pathlib,sys\n"
        "paths={name:os.environ.get(name) for name in ('TELEMT_API_TOKEN_FILE','MIERU_MANAGER_TOKEN_FILE','PANEL_MASTER_KEY_FILE','TRUSTTUNNEL_MANAGER_TOKEN_FILE')}\n"
        "metadata={name:[pathlib.Path(path).read_text(),pathlib.Path(path).stat().st_uid,pathlib.Path(path).stat().st_gid,pathlib.Path(path).stat().st_mode&511] for name,path in paths.items() if path}\n"
        "pathlib.Path(os.environ['LAUNCH_LOG']).write_text(json.dumps({'args':sys.argv[1:],'paths':paths,'metadata':metadata}))\n"
    )
    install.chmod(0o755)
    launch.chmod(0o755)
    sources = {}
    for name in ("telemt", "mieru", "master", "trust"):
        path = tmp_path / name
        path.write_text("m" * 32)
        path.chmod(0o440)
        os.chown(path, 0, 10005)
        sources[name] = path
    # Prove the disabled manager is not validated at all.
    if not enabled:
        sources["mieru"].chmod(0o600)
    override = tmp_path / "attacker-runtime"
    override.mkdir()
    sentinel = override / "mieru-manager-token"
    sentinel.write_text("untouched")
    log = tmp_path / "launch.json"
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin", "LAUNCH_LOG": str(log),
        "PANEL_SUPPLEMENTARY_GROUPS": groups, "MIERU_ENABLED": str(enabled).lower(),
        "TELEMT_API_TOKEN_SOURCE": str(sources["telemt"]),
        "MIERU_MANAGER_TOKEN_SOURCE": str(sources["mieru"]),
        "PANEL_MASTER_KEY_SOURCE": str(sources["master"] if master else tmp_path / "absent-master"),
        "TRUSTTUNNEL_MANAGER_TOKEN_SOURCE": str(sources["trust"] if trust else tmp_path / "absent-trust"),
        "PANEL_RUNTIME_DIR": str(override),
    }
    result = subprocess.run(
        ["unshare", "--mount", "--propagation", "private", "/bin/sh", "-eu", "-c",
         'mount -t tmpfs none /run; mount -t tmpfs none /usr/local/bin; cp "$1" /usr/local/bin/panel; exec /bin/sh "$2"',
         "entrypoint-test", str(panel_binary), str(ROOT / "panel/entrypoint.sh")],
        env=env, text=True, capture_output=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    recorded = json.loads(log.read_text())
    assert recorded["args"][-1] == "/usr/local/bin/panel"
    assert "--no-new-privs" in recorded["args"]
    if groups:
        assert recorded["args"][recorded["args"].index("--groups") + 1] == groups
    else:
        assert "--clear-groups" in recorded["args"]
    for name, present in (("MIERU_MANAGER_TOKEN_FILE", enabled), ("PANEL_MASTER_KEY_FILE", master),
                          ("TRUSTTUNNEL_MANAGER_TOKEN_FILE", trust)):
        assert (recorded["paths"][name] is not None) == present
    for name, values in recorded["metadata"].items():
        assert recorded["paths"][name].startswith("/run/panel/")
        assert values == ["m" * 32, 10001, 101, 0o400]
    assert sentinel.read_text() == "untouched"
