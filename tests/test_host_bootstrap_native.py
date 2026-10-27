"""Public host shell acceptance. Python is only the lab harness, absent from child PATH.

No test executes sudo or touches installed paths. Fixtures are private unprivileged release
bundles; real native CLI checks use the installer executable supplied by the isolated build.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

import pytest

ROOT = Path(__file__).parents[1]
INSTALLER = "installer/bin/linux-amd64/proxy-control-installer"
AGENT = "version_agent/bin/linux-amd64/proxy-control-version-agent"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


@pytest.fixture
def private_bundle():
    with tempfile.TemporaryDirectory(prefix="pc-host-bootstrap-", dir="/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        yield root


def _malformed_object(data, change):
    if change == "missing-comma":
        return data.replace(b'",\n', b'"\n', 1)
    if change == "trailing-comma":
        return data.replace(b'\n}', b',\n}', 1)
    if change == "duplicate-close":
        return data + b"}\n"
    raise AssertionError(change)


def _bundle(root, *, version="4.0.0", mode=0o755, bad_digest=False, member=None, duplicate_manifest=False,
            manifest_syntax=None, binary_syntax=None):
    source = root / "dist"
    source.mkdir()
    native = Path("/bin/true").read_bytes()
    identity = {"version": version, "tag": "v" + version, "commit": "a" * 40, "manifest_sha256": "b" * 64,
                "binaries": {INSTALLER: "0" * 64 if bad_digest else _sha(native), AGENT: _sha(native)}}
    files = {"install.sh": (ROOT / "install.sh").read_bytes(), "VERSION": (version + "\n").encode(),
             "release/release.json": _json(identity), INSTALLER: native, AGENT: native}
    if binary_syntax:
        identity_data = files["release/release.json"]
        if binary_syntax == "missing-comma":
            identity_data = identity_data.replace(b'",\n', b'"\n', 1)
        else:
            assert binary_syntax == "trailing-comma"
            identity_data = identity_data.replace(b'"\n  }', b'",\n  }', 1)
        files["release/release.json"] = identity_data
    archive = source / f"proxy-control-v{version}.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for name, content in files.items():
            info = tarfile.TarInfo("proxy-control/" + name)
            info.mode = mode if name == INSTALLER else 0o755 if name in (AGENT, "install.sh") else 0o644
            info.size = len(content)
            output.addfile(info, io.BytesIO(content))
        if member:
            name, kind = member
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.REGTYPE
            info.linkname = "/tmp/escape" if kind == "symlink" else ""
            output.addfile(info, io.BytesIO())
    manifest = {"archive": archive.name, "archive_sha256": _sha(archive.read_bytes()), "version": version,
                "tag": "v" + version, "schema": 1, "file_count": len(files), "source_epoch": 1,
                "commit": "a" * 40, "external_manifest_sha256": "b" * 64}
    data = _json(manifest)
    if duplicate_manifest:
        data = data.replace(b'{\n', b'{\n  "version": "9.9.9",\n', 1)
    if manifest_syntax:
        data = _malformed_object(data, manifest_syntax)
    (source / "release-manifest.json").write_bytes(data)
    (source / "sbom.spdx.json").write_bytes(b"{}\n")
    checksums = "".join(f"{_sha((source / name).read_bytes())}  {name}\n"
                        for name in (archive.name, "release-manifest.json", "sbom.spdx.json"))
    (source / "SHA256SUMS").write_text(checksums)
    return source, archive


def _run(root, source, archive, *, bootstrap=False, version="4.0.0"):
    binary = root / "bin"
    binary.mkdir()
    # An allowlist, not /usr/bin appended to PATH: a Python/Cargo dependency cannot hide.
    for tool in ("bash", "awk", "curl", "tar", "gzip", "sha256sum", "cut", "stat", "mkdir", "chmod", "cp",
                 "dirname", "basename", "mktemp", "cat", "tr", "uname", "id"):
        target = shutil.which(tool)
        assert target, tool
        (binary / tool).symlink_to(target)
    log = root / "sudo.log"
    (binary / "sudo").write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" > '{log}'\n")
    (binary / "sudo").chmod(0o755)
    script = root / "entrypoint"
    shutil.copy2(ROOT / ("install-bootstrap" if bootstrap else "scripts/install-release.sh"), script)
    if os.geteuid() == 0:
        for path in (root, *root.rglob("*")):
            if not path.is_symlink():
                os.chown(path, 65534, 65534)
    def unprivileged():
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
    if bootstrap:
        args = ["--archive", str(archive), "--checksum", str(source / "SHA256SUMS"), "--manifest", str(source / "release-manifest.json"),
                "--destination", str(root / "output")]
    else:
        args = ["--version", version, "--from-dir", str(source), "--dir", str(root / "output"), "--no-wizard"]
    result = subprocess.run(["/bin/bash", str(script), *args], cwd=root,
                            env={"PATH": str(binary), "LANG": "C", "TMPDIR": str(root)},
                            preexec_fn=unprivileged, capture_output=True, text=True, timeout=30)
    return result, log


@pytest.mark.parametrize("bootstrap", [False, True])
def test_verification_has_no_host_python_or_cargo_prerequisite(private_bundle, bootstrap):
    source, archive = _bundle(private_bundle)
    result, log = _run(private_bundle, source, archive, bootstrap=bootstrap)
    assert result.returncode == 0, result.stderr
    assert "verified:" in result.stdout or "verified " in result.stdout
    assert (private_bundle / "output/proxy-control" / INSTALLER).is_file()
    assert log.exists() == bootstrap
    assert not (private_bundle / "bin/python3").exists()
    assert not (private_bundle / "bin/cargo").exists()


@pytest.mark.parametrize("bootstrap", [False, True])
@pytest.mark.parametrize("change", [{"mode": 0o644}, {"bad_digest": True}, {"member": ("proxy-control/link", "symlink")},
                                  {"member": ("proxy-control/../escape", "file")}, {"duplicate_manifest": True}])
def test_untrusted_or_unverified_binary_never_reaches_sudo(private_bundle, bootstrap, change):
    source, archive = _bundle(private_bundle, **change)
    result, log = _run(private_bundle, source, archive, bootstrap=bootstrap)
    assert result.returncode != 0, result.stdout
    assert not log.exists()


@pytest.mark.parametrize("bootstrap", [False, True])
@pytest.mark.parametrize("change", [{"manifest_syntax": "missing-comma"}, {"manifest_syntax": "trailing-comma"},
                                  {"manifest_syntax": "duplicate-close"}, {"binary_syntax": "missing-comma"},
                                  {"binary_syntax": "trailing-comma"}])
def test_malformed_verification_objects_never_reach_sudo(private_bundle, bootstrap, change):
    source, archive = _bundle(private_bundle, **change)
    result, log = _run(private_bundle, source, archive, bootstrap=bootstrap)
    assert result.returncode != 0, result.stdout
    assert not log.exists()


def test_stable_bootstrap_refuses_prerelease(private_bundle):
    source, archive = _bundle(private_bundle, version="4.0.0-rc.1")
    result, log = _run(private_bundle, source, archive, bootstrap=True)
    assert result.returncode != 0 and "stable releases only" in result.stderr
    assert not log.exists()


def test_release_verifier_allows_private_local_prerelease_rehearsal(private_bundle):
    source, archive = _bundle(private_bundle, version="4.0.0-rc.1")
    result, log = _run(private_bundle, source, archive, version="4.0.0-rc.1")
    assert result.returncode == 0, result.stderr
    assert not log.exists()


@pytest.mark.parametrize("script,command", [("install.sh", None), ("uninstall.sh", "uninstall"),
                                          ("scripts/update-host.sh", "update-host"),
                                          ("scripts/migrate-compose-project.sh", "migrate-compose-project")])
def test_shell_shims_dispatch_real_native_cli_in_private_tree(private_bundle, script, command):
    executable = os.environ.get("PROXY_CONTROL_TEST_INSTALLER")
    assert executable and Path(executable).is_file(), "set PROXY_CONTROL_TEST_INSTALLER to the isolated Rust build"
    tree = private_bundle / "tree"
    (tree / "scripts").mkdir(parents=True)
    for name in ("install.sh", "uninstall.sh", "scripts/update-host.sh", "scripts/migrate-compose-project.sh"):
        shutil.copy2(ROOT / name, tree / name)
    target = tree / INSTALLER
    target.parent.mkdir(parents=True)
    shutil.copy2(executable, target)
    tools = private_bundle / "tools"
    tools.mkdir()
    for tool in ("bash", "dirname", "uname", "id"):
        target = shutil.which(tool)
        assert target, tool
        (tools / tool).symlink_to(target)
    result = subprocess.run(["/bin/bash", str(tree / script), "--help"],
                            env={"PATH": str(tools), "LANG": "C"}, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    if command:
        assert command in result.stdout


@pytest.mark.parametrize("language", ["en", "ru"])
def test_native_wizard_router_question_names_the_current_manifest_pin(private_bundle, language):
    executable = os.environ.get("PROXY_CONTROL_TEST_INSTALLER")
    assert executable and Path(executable).is_file(), "set PROXY_CONTROL_TEST_INSTALLER to the isolated Rust build"
    tree = private_bundle / "tree"
    target = tree / INSTALLER
    target.parent.mkdir(parents=True)
    shutil.copy2(executable, target)
    manifest = json.loads((ROOT / "release/external-artifacts.json").read_text())
    (tree / "release").mkdir()
    (tree / "release/external-artifacts.json").write_text(json.dumps(manifest))
    pin = next(item["version"] for item in manifest["artifacts"] if item["name"] == "xray")
    root = private_bundle / "root"
    root.mkdir()
    output = private_bundle / "never-saved.toml"
    answers = ["fresh", "core", "none", "panel.example.com", "relay.example.com", "", "",
               "no", "yes", "gate.example.com", "quit"]
    result = subprocess.run(
        [str(target), "--root", str(root), "wizard", "--lang", language, "--config-output", str(output)],
        input="\n".join(answers) + "\n", capture_output=True, text=True, timeout=20,
        env={"PATH": os.environ["PATH"], "LANG": "C"},
    )
    assert result.returncode == 0, result.stderr
    assert f"Xray-core {pin}" in result.stdout, result.stdout
    assert not output.exists()
