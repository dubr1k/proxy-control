from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest

import release.build as release_build
from release.build import (
    BuiltRelease,
    HOST_BINARIES_DOCKERFILE,
    HOST_BINARIES_LIST,
    HOST_BINARY_BUILDER,
    HOST_BINARY_DIGESTS,
    INSTALLER_CHECKSUM_NAME,
    INSTALLER_NAME,
    MANIFEST_NAME,
    SBOM_NAME,
    ReleaseBuildError,
    build_release,
    builder_image,
    host_crates,
    tracked_files,
    verify_archive_binaries,
    verify_release,
)
from release.sbom import SbomError, build_sbom


ROOT = Path(__file__).parents[1]
FIXED_EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z
VERSION = "3.2.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tar_names(archive: Path) -> tuple[str, ...]:
    with tarfile.open(archive, mode="r:gz") as handle:
        return tuple(sorted(handle.getnames()))


def top_level_names(names: tuple[str, ...]) -> set[str]:
    return {
        name.split("/", 2)[1]
        for name in names
        if name.startswith("proxy-control/") and "/" in name[len("proxy-control/") :]
    } | {
        name[len("proxy-control/") :]
        for name in names
        if name.startswith("proxy-control/")
        and "/" not in name[len("proxy-control/") :]
    }


def git(root: Path, *arguments: str) -> None:
    subprocess.run(("git", "-C", str(root), *arguments), check=True, capture_output=True)


def clean_checkout(tmp_path: Path, name: str = "source") -> Path:
    """A tiny committed tree that behaves like the real repository."""
    root = tmp_path / name
    (root / "release").mkdir(parents=True)
    (root / "installer").mkdir()
    (root / "VERSION").write_text(f"{VERSION}\n")
    (root / "install.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    (root / "install.sh").chmod(0o755)
    (root / "README.md").write_text("# release fixture\n")
    # The real install script: the release stamps it and publishes it beside the archive.
    (root / "scripts").mkdir()
    (root / "scripts" / "install-release.sh").write_bytes((ROOT / "scripts" / "install-release.sh").read_bytes())
    (root / "scripts" / "install-release.sh").chmod(0o755)
    (root / ".gitignore").write_text(
        ".env\nsecrets/\n.lab-state/\nlab-results/\n__pycache__/\n*.pyc\n"
    )
    (root / "release" / "external-artifacts.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifacts": [
                    {
                        "name": "mita",
                        "version": "3.36.0",
                        "tag": "v3.36.0",
                        "repository": "enfein/mieru",
                        "spdx_license": "GPL-3.0-or-later",
                        "platforms": {
                            "amd64": {
                                "architecture": "amd64",
                                "url": "https://example.invalid/mita_amd64.deb",
                                "sha256": "a" * 64,
                                "executable_path": "usr/bin/mita",
                                "executable_sha256": "b" * 64,
                            }
                        },
                    },
                    {
                        "name": "xray",
                        "version": "26.3.27",
                        "tag": "v26.3.27",
                        "repository": "XTLS/Xray-core",
                        "spdx_license": "MPL-2.0",
                        "platforms": {
                            "amd64": {
                                "architecture": "amd64",
                                "filename_architecture": "64",
                                "url": "https://example.invalid/Xray-linux-64.zip",
                                "sha256": "c" * 64,
                                "members": {
                                    "xray": {"sha256": "d" * 64, "size": 3, "mode": "0755"},
                                    "geoip.dat": {"sha256": "e" * 64, "size": 3, "mode": "0644"},
                                },
                            }
                        },
                    },
                ],
            },
            indent=2,
        )
        + "\n"
    )
    git(root.parent, "init", "-q", name)
    git(root, "config", "user.email", "lab@example.invalid")
    git(root, "config", "user.name", "release fixture")
    git(root, "add", "-A")
    git(
        root,
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "release fixture",
    )
    return root


def checkout_with_private_files(tmp_path: Path) -> Path:
    """The same tree plus the private and lab state a release must exclude."""
    root = clean_checkout(tmp_path, name="dirty-source")
    (root / ".env").write_text("PANEL_ALLOWED_HOSTS=panel.example.com\n")
    (root / "secrets").mkdir()
    (root / "secrets" / "users.conf").write_text("owner=deadbeef\n")
    (root / ".lab-state").mkdir()
    (root / ".lab-state" / "ssh-key").write_text("private\n")
    (root / "lab-results").mkdir()
    (root / "lab-results" / "report.json").write_text("{}\n")
    (root / "installer" / "__pycache__").mkdir()
    (root / "installer" / "__pycache__" / "cli.pyc").write_bytes(b"\x00")
    return root


def build(tmp_path: Path, output: str, source: Path, **kwargs) -> BuiltRelease:
    return build_release(
        tmp_path / output,
        source=source,
        version=VERSION,
        epoch=FIXED_EPOCH,
        **kwargs,
    )


# ----------------------------------------------------------------------
# reproducibility
# ----------------------------------------------------------------------


def test_two_release_builds_are_byte_identical(tmp_path):
    source = clean_checkout(tmp_path)
    first = build(tmp_path, "one", source)
    second = build(tmp_path, "two", source)
    assert sha256(first.archive) == sha256(second.archive)
    assert first.manifest_bytes == second.manifest_bytes
    assert first.sbom_bytes == second.sbom_bytes


def test_the_release_builds_twice_into_the_checkout_the_way_ci_does(tmp_path):
    """The published build runs twice into `dist/` and `dist-again/` inside the
    checkout and compares the bytes. The second build re-checks that the tree is
    clean, so the first build's output must be ignored or it refuses itself."""
    source = clean_checkout(tmp_path)
    (source / ".gitignore").write_text(
        (source / ".gitignore").read_text() + "dist/\ndist-again/\n"
    )
    git(source, "add", ".gitignore")
    git(source, "commit", "-qm", "ignore release outputs")

    first = build_release(
        source / "dist", source=source, version=VERSION, epoch=FIXED_EPOCH
    )
    second = build_release(
        source / "dist-again", source=source, version=VERSION, epoch=FIXED_EPOCH
    )

    assert sha256(first.archive) == sha256(second.archive)


def test_the_repository_ignores_its_own_release_outputs():
    """The same property, on the real .gitignore rather than a fixture."""
    for name in ("dist", "dist-again"):
        completed = subprocess.run(
            ("git", "-C", str(ROOT), "check-ignore", "-q", f"{name}/"),
            capture_output=True,
        )
        assert completed.returncode == 0, name


def test_release_excludes_untracked_ignored_private_and_lab_state(tmp_path):
    source = checkout_with_private_files(tmp_path)
    archive = build(tmp_path, "dist", source).archive
    names = tar_names(archive)
    assert not {
        ".git",
        ".env",
        "secrets",
        ".lab-state",
        "lab-results",
    } & top_level_names(names)
    assert not any(name.endswith(".pyc") for name in names)


def test_archive_members_are_root_owned_with_the_commit_timestamp(tmp_path):
    source = clean_checkout(tmp_path)
    archive = build(tmp_path, "dist", source).archive
    with tarfile.open(archive, mode="r:gz") as handle:
        members = handle.getmembers()
    assert members
    for member in members:
        assert member.uid == 0 and member.gid == 0
        assert member.uname == "root" and member.gname == "root"
        assert member.mtime == FIXED_EPOCH
        assert member.mode in {0o644, 0o755}
        assert member.name.startswith("proxy-control/")


def test_the_git_executable_bit_is_the_only_source_of_mode(tmp_path):
    source = clean_checkout(tmp_path)
    archive = build(tmp_path, "dist", source).archive
    with tarfile.open(archive, mode="r:gz") as handle:
        modes = {member.name: member.mode for member in handle.getmembers()}
    assert modes["proxy-control/install.sh"] == 0o755
    assert modes["proxy-control/README.md"] == 0o644


def test_a_release_carries_its_own_identity(tmp_path):
    source = clean_checkout(tmp_path)
    built = build(tmp_path, "dist", source)
    with tarfile.open(built.archive, mode="r:gz") as handle:
        extracted = handle.extractfile("proxy-control/release/release.json")
        assert extracted is not None
        identity = json.loads(extracted.read())
    assert identity["version"] == VERSION
    assert identity["tag"] == f"v{VERSION}"
    assert identity["commit"] == built.commit
    assert len(identity["manifest_sha256"]) == 64
    assert identity["components"]["mita"] == "3.36.0"


def test_the_manifest_and_checksums_describe_the_built_archive(tmp_path):
    source = clean_checkout(tmp_path)
    built = build(tmp_path, "dist", source)
    manifest = json.loads(built.manifest.read_text())
    assert manifest["archive"] == built.archive.name
    assert manifest["archive_sha256"] == sha256(built.archive)
    assert manifest["version"] == VERSION
    recorded = dict(
        line.split("  ", 1)[::-1]
        for line in built.checksums.read_text().splitlines()
    )
    assert set(recorded) == {
        built.archive.name,
        MANIFEST_NAME,
        SBOM_NAME,
    }
    assert recorded[built.archive.name] == sha256(built.archive)


def test_verify_release_accepts_a_built_dist_and_rejects_a_tampered_one(tmp_path):
    source = clean_checkout(tmp_path)
    built = build(tmp_path, "dist", source)
    assert verify_release(tmp_path / "dist").archive_sha256 == built.archive_sha256

    built.archive.write_bytes(built.archive.read_bytes() + b"tampered")
    with pytest.raises(ReleaseBuildError, match="digest does not match"):
        verify_release(tmp_path / "dist")


def test_the_release_publishes_its_install_script_stamped_with_its_own_identity(tmp_path):
    """`install-release.sh` beside the archive installs exactly that release: its version
    and archive digest are stamped in; the repository's copy keeps both empty."""
    source = clean_checkout(tmp_path)
    built = build(tmp_path, "dist", source)
    script = (tmp_path / "dist" / INSTALLER_NAME).read_text()
    assert f'\nSTAMPED_VERSION="{VERSION}"\n' in script
    assert f'\nSTAMPED_SHA256="{built.archive_sha256}"\n' in script
    assert os.access(tmp_path / "dist" / INSTALLER_NAME, os.X_OK)
    recorded = (tmp_path / "dist" / INSTALLER_CHECKSUM_NAME).read_text()
    assert recorded == f"{sha256(tmp_path / 'dist' / INSTALLER_NAME)}  {INSTALLER_NAME}\n"
    # Apart from the two stamps the published copy is the tracked script, byte for byte.
    original = (source / "scripts" / "install-release.sh").read_text()
    assert script.replace(f'"{VERSION}"', '""', 1).replace(f'"{built.archive_sha256}"', '""', 1) == original
    # SHA256SUMS still names the three files earlier install scripts check strictly.
    names = {line.split("  ", 1)[1] for line in built.checksums.read_text().splitlines()}
    assert names == {built.archive.name, MANIFEST_NAME, SBOM_NAME}
    repository = (ROOT / "scripts" / "install-release.sh").read_text()
    assert '\nSTAMPED_VERSION=""\n' in repository and '\nSTAMPED_SHA256=""\n' in repository


def test_verify_refuses_an_install_script_changed_or_stamped_for_another_release(tmp_path):
    source = clean_checkout(tmp_path)
    build(tmp_path, "dist", source)
    dist = tmp_path / "dist"
    script = dist / INSTALLER_NAME
    original = script.read_bytes()
    script.write_bytes(original + b"\n# changed\n")
    with pytest.raises(ReleaseBuildError, match="does not match"):
        verify_release(dist)
    restamped = original.replace(f'STAMPED_VERSION="{VERSION}"'.encode(), b'STAMPED_VERSION="9.9.9"')
    script.write_bytes(restamped)
    (dist / INSTALLER_CHECKSUM_NAME).write_text(f"{hashlib.sha256(restamped).hexdigest()}  {INSTALLER_NAME}\n")
    with pytest.raises(ReleaseBuildError, match="another release"):
        verify_release(dist)


def _run_published_script(dist: Path, *arguments: str) -> subprocess.CompletedProcess:
    """The published copy, run the way an operator runs it: unprivileged, from a fresh
    directory, on files already downloaded (`--from-dir`), never past `--no-wizard`."""
    import shutil
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="install-release-"))
    try:
        work.chmod(0o755)
        shutil.copytree(dist, work / "dist")
        command = ["bash", str(work / "dist" / INSTALLER_NAME), "--from-dir", str(work / "dist"),
                   "--dir", str(work / "out"), "--lang", "en", "--no-wizard", *arguments]
        if os.geteuid() == 0:
            # The script refuses root by design; the suite on the lab host runs as root.
            for path in [work, *work.rglob("*")]:
                os.chown(path, 65534, 65534)
            command = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", *command]
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8"}
        result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True, timeout=120)
        extracted = (work / "out" / "proxy-control" / "release" / "release.json").is_file()
        result.stdout += f"\nEXTRACTED={extracted}\n"
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_the_published_install_script_installs_its_own_release_and_refuses_other_bytes(tmp_path):
    source = checkout_with_host_crates(tmp_path)
    agent = source / "version_agent"
    agent.mkdir()
    (agent / "Cargo.toml").write_text('[package]\nname = "version_agent"\n')
    (agent / "Cargo.lock").write_bytes((ROOT / "version_agent/Cargo.lock").read_bytes())
    git(source, "add", "-A")
    git(source, "commit", "-qm", "both shipped native host binaries")
    built = build(
        tmp_path, "dist", source,
        binaries_from=fake_build(tmp_path / "bin", {
            PROBE: b"\x7fELF fixture installer",
            "version_agent/bin/linux-amd64/proxy-control-version-agent": b"\x7fELF fixture version-agent",
        }),
    )
    dist = tmp_path / "dist"
    ok = _run_published_script(dist)
    assert ok.returncode == 0, ok.stderr
    assert f"verified: {built.archive.name} ({built.archive_sha256})" in ok.stdout
    assert "EXTRACTED=True" in ok.stdout

    # Someone swaps the archive and rewrites SHA256SUMS and the manifest to match: the
    # stamped digest still refuses it before anything is extracted.
    forged = dist / built.archive.name
    forged.write_bytes(gzip_rewrap(forged.read_bytes()))
    digest = sha256(forged)
    manifest = json.loads((dist / MANIFEST_NAME).read_text())
    manifest["archive_sha256"] = digest
    (dist / MANIFEST_NAME).write_text(json.dumps(manifest))
    (dist / "SHA256SUMS").write_text("".join(
        f"{sha256(dist / name)}  {name}\n" for name in (built.archive.name, MANIFEST_NAME, SBOM_NAME)
    ))
    refused = _run_published_script(dist)
    assert refused.returncode != 0
    assert f"archive digest {digest}" in refused.stderr and built.archive_sha256 in refused.stderr
    assert "EXTRACTED=False" in refused.stdout

    # Another release asked for explicitly is not held to this release's digest.
    other = _run_published_script(dist, "--version", "9.9.9")
    assert "9.9.9" in other.stderr and built.archive_sha256 not in other.stderr


def gzip_rewrap(data: bytes) -> bytes:
    """The same tar, compressed again with another level: different bytes, still valid."""
    import gzip

    return gzip.compress(gzip.decompress(data), compresslevel=1, mtime=0)


# ----------------------------------------------------------------------
# refusals
# ----------------------------------------------------------------------


def test_a_dirty_tree_is_refused_in_release_mode(tmp_path):
    source = clean_checkout(tmp_path)
    (source / "README.md").write_text("# uncommitted\n")
    with pytest.raises(ReleaseBuildError, match="dirty tree"):
        build_release(
            tmp_path / "dist",
            source=source,
            version=VERSION,
            epoch=FIXED_EPOCH,
        )


def test_a_version_mismatch_is_refused(tmp_path):
    source = clean_checkout(tmp_path)
    with pytest.raises(ReleaseBuildError, match="VERSION declares"):
        build_release(
            tmp_path / "dist",
            source=source,
            version="9.9.9",
            epoch=FIXED_EPOCH,
        )


@pytest.mark.parametrize("marker", [None, "0.0.0\n"])
def test_rust_panel_release_refuses_missing_or_stale_shared_generation(tmp_path, marker):
    source = clean_checkout(tmp_path)
    (source / "panel").mkdir()
    (source / "panel/Cargo.toml").write_text('[workspace]\nmembers = ["crates/*"]\n')
    if marker is not None:
        (source / "pc_common").mkdir()
        (source / "pc_common/RELEASE").write_text(marker)
    git(source, "add", "-A")
    git(source, "commit", "-qm", "Rust panel generation fixture")
    with pytest.raises(ReleaseBuildError, match="pc_common/RELEASE must match VERSION"):
        build(tmp_path, "dist", source)


def test_a_non_semantic_version_is_refused(tmp_path):
    source = clean_checkout(tmp_path)
    with pytest.raises(ReleaseBuildError, match="must be semantic"):
        build_release(
            tmp_path / "dist",
            source=source,
            version="latest",
            epoch=FIXED_EPOCH,
        )


def test_a_tracked_private_path_is_refused(tmp_path):
    source = clean_checkout(tmp_path)
    (source / "secrets").mkdir()
    (source / "secrets" / "users.conf").write_text("owner=deadbeef\n")
    git(source, "add", "-f", "secrets/users.conf")
    git(source, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "oops")
    with pytest.raises(ReleaseBuildError, match="must not contain secrets"):
        tracked_files(source)


# ----------------------------------------------------------------------
# SBOM
# ----------------------------------------------------------------------


def test_sbom_lists_every_file_and_pinned_external_artifact(tmp_path):
    source = clean_checkout(tmp_path)
    built = build(tmp_path, "dist", source)
    document = json.loads(built.sbom.read_text())
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    names = {package["name"] for package in document["packages"]}
    assert "proxy-control" in names
    assert "mita-amd64" in names
    mita = next(item for item in document["packages"] if item["name"] == "mita-amd64")
    assert mita["licenseDeclared"] == "GPL-3.0-or-later"
    assert {entry["checksumValue"] for entry in mita["checksums"]} == {
        "a" * 64,
        "b" * 64,
    }
    xray = next(item for item in document["packages"] if item["name"] == "xray-amd64")
    assert xray["licenseDeclared"] == "MPL-2.0"
    assert {entry["checksumValue"] for entry in xray["checksums"]} == {"c" * 64, "d" * 64, "e" * 64}
    files = {entry["fileName"] for entry in document["files"]}
    assert "./install.sh" in files
    assert "./release/release.json" in files
    kinds = {item["relationshipType"] for item in document["relationships"]}
    assert kinds == {"DESCRIBES", "CONTAINS", "DEPENDS_ON"}


def test_sbom_is_deterministic_for_one_commit():
    external = ROOT / "release" / "external-artifacts.json"
    first = build_sbom(
        version=VERSION,
        commit="c" * 40,
        files={"install.sh": "d" * 64},
        external=external,
        epoch=FIXED_EPOCH,
    )
    second = build_sbom(
        version=VERSION,
        commit="c" * 40,
        files={"install.sh": "d" * 64},
        external=external,
        epoch=FIXED_EPOCH,
    )
    assert first == second
    assert b"2026-01-01T00:00:00Z" in first


def test_sbom_requires_at_least_one_packaged_file():
    with pytest.raises(SbomError, match="at least one packaged file"):
        build_sbom(
            version=VERSION,
            commit="c" * 40,
            files={},
            external=ROOT / "release" / "external-artifacts.json",
            epoch=FIXED_EPOCH,
        )


# ----------------------------------------------------------------------
# bootstrap and workflow structure
# ----------------------------------------------------------------------


def test_release_workflow_pins_actions_and_separates_privileged_jobs():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    for job in (
        "quality:",
        "build-twice-and-compare:",
        "attest:",
        "draft-release:",
        "publish:",
    ):
        assert job in workflow
    # The lab host is the gate: CI only confirms it built the bytes the lab accepted,
    # from a dispatch input or the annotated tag, and no QEMU lab job sits in the chain.
    assert "lab-amd64:" not in workflow
    assert "expected_sha256:" in workflow
    assert "lab-sha256:" in workflow
    assert 'test "$first" = "$expected"' in workflow
    assert "needs: [build-twice-and-compare]" in workflow
    assert '- "v[0-9]+.[0-9]+.[0-9]+"' in workflow
    assert '- "v[0-9]+.[0-9]+.[0-9]+-*"' in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "contents: write" in workflow
    assert "environment:" in workflow
    # Every third-party action is pinned to a commit SHA, never a tag.
    for line in workflow.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:") and not stripped.startswith("uses: ./"):
            reference = stripped.split("@", 1)[1].split()[0]
            assert len(reference) == 40, stripped
            assert all(character in "0123456789abcdef" for character in reference)


@pytest.mark.parametrize("language", ["en", "ru"])
def test_the_install_script_names_exactly_the_pinned_artifact_versions(language):
    """The actual requirements output must agree with the current release manifest."""
    import re

    pins = {
        item["name"]: item["version"]
        for item in json.loads((ROOT / "release" / "external-artifacts.json").read_text())["artifacts"]
    }
    completed = subprocess.run(
        ("bash", str(ROOT / "scripts" / "install-release.sh"), "--requirements", "--lang", language),
        check=True, capture_output=True, text=True, timeout=10,
    )
    named = {
        "three_xui": re.findall(r"3x-ui ([0-9][0-9.]*[0-9])", completed.stdout),
        "mita": re.findall(r"mita_([0-9][0-9A-Za-z.\-]*)_amd64\.deb", completed.stdout),
        "mieru": re.findall(r"mieru_([0-9][0-9A-Za-z.\-]*)_amd64\.deb", completed.stdout),
        "xray": re.findall(r"Xray-core ([0-9][0-9.]*[0-9])", completed.stdout),
        "trusttunnel": re.findall(r"TrustTunnel endpoint ([0-9][0-9.]*[0-9])", completed.stdout),
    }
    for name, versions in named.items():
        assert versions, f"{name}: {language} requirements must name the pinned version"
        assert set(versions) == {pins[name]}, f"{name}: the script says {sorted(set(versions))}, the pin is {pins[name]}"


# ----------------------------------------------------------------------
# prebuilt host binaries (release/host-binaries.list, release/Dockerfile.host-binaries)
# ----------------------------------------------------------------------

PROBE = "installer/bin/linux-amd64/proxy-control-installer"
LIBRARY_FILE = "pc_common/src/lib.rs"


def checkout_with_host_crates(tmp_path: Path) -> Path:
    """The fixture tree plus the real list, the real Dockerfile, an installer crate with the real
    Cargo.lock and a shared library crate: what the release builder sees in the repository."""
    root = clean_checkout(tmp_path, name="crate-source")
    for name in (HOST_BINARIES_LIST, HOST_BINARIES_DOCKERFILE, "installer/Cargo.lock"):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes((ROOT / name).read_bytes())
    (root / "installer/Cargo.toml").write_text('[package]\nname = "installer"\n')
    (root / "installer/src").mkdir()
    (root / "installer/src/main.rs").write_text("fn main() {}\n")
    (root / "pc_common/src").mkdir(parents=True)
    (root / "pc_common/Cargo.toml").write_text('[package]\nname = "pc_common"\n')
    (root / LIBRARY_FILE).write_text("\n")
    (root / "unrelated").mkdir()
    (root / "unrelated/notes.txt").write_text("not a crate\n")
    git(root, "add", "-A")
    git(root, "-c", "commit.gpgsign=false", "commit", "-qm", "host crates")
    return root


def fake_build(directory: Path, binaries: dict[str, bytes], *, image: str | None = None) -> Path:
    """A directory shaped like the builder's output, with stand-in bytes."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in binaries.items():
        (directory / name).parent.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(data)
        (directory / name).chmod(0o755)
    (directory / HOST_BINARY_DIGESTS).write_text(
        "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(binaries.items()))
    )
    (directory / HOST_BINARY_BUILDER).write_text(
        f"image {image or builder_image(ROOT)}\ntarget x86_64-unknown-linux-musl\n"
        "rustc rustc 1.99.1 (58cf8f9c3 2026-10-13)\n"
    )
    return directory


@pytest.fixture
def no_docker(monkeypatch):
    def refuse(command):
        raise AssertionError(f"the builder must not run: {command}")

    monkeypatch.setattr(release_build, "_run_builder", refuse)


def archive_member(archive: Path, name: str) -> tuple[int, bytes]:
    with tarfile.open(archive, mode="r:gz") as handle:
        member = handle.getmember(f"proxy-control/{name}")
        extracted = handle.extractfile(member)
        assert extracted is not None
        return member.mode, extracted.read()


def identity_of(archive: Path) -> dict:
    return json.loads(archive_member(archive, "release/release.json")[1])


def test_a_tree_without_host_crates_builds_no_binaries_and_keeps_its_identity_bytes(tmp_path, no_docker):
    """The fixture tree has no list: no builder runs, and release.json has no new keys, so a
    release without host crates is byte-for-byte what it was before host binaries existed."""
    source = clean_checkout(tmp_path)
    identity = identity_of(build(tmp_path, "dist", source).archive)
    assert "binaries" not in identity and "builder" not in identity


def test_only_listed_crates_with_a_tracked_cargo_toml_take_part(tmp_path):
    source = checkout_with_host_crates(tmp_path)
    crates = host_crates(source, tracked_files(source))
    # This small fixture deliberately omits the listed version-agent crate.
    assert crates.libraries == ("pc_common",)
    assert crates.binaries == (("installer", "proxy-control-installer"),)
    assert crates.paths == (PROBE,)


def test_binaries_from_injects_executable_members_and_records_them(tmp_path, no_docker):
    source = checkout_with_host_crates(tmp_path)
    probe = b"\x7fELF stand-in probe"
    built = build(tmp_path, "dist", source, binaries_from=fake_build(tmp_path / "bin", {PROBE: probe}))

    mode, data = archive_member(built.archive, PROBE)
    assert (mode, data) == (0o755, probe)
    identity = identity_of(built.archive)
    assert identity["binaries"] == {PROBE: hashlib.sha256(probe).hexdigest()}
    assert identity["builder"] == {
        "image": builder_image(ROOT),
        "rustc": "rustc 1.99.1 (58cf8f9c3 2026-10-13)",
        "target": "x86_64-unknown-linux-musl",
    }
    assert identity["schema"] == 1
    # Tracked files keep the git executable bit as their only mode source.
    assert archive_member(built.archive, "installer/Cargo.toml")[0] == 0o644

    document = json.loads(built.sbom.read_text())
    files = {entry["fileName"]: entry["checksums"][0]["checksumValue"] for entry in document["files"]}
    assert files[f"./{PROBE}"] == hashlib.sha256(probe).hexdigest()
    ring = next(item for item in document["packages"] if item["name"] == "ring")
    assert ring["downloadLocation"].startswith("https://crates.io/api/v1/crates/ring/")
    assert ring["externalRefs"][0]["referenceLocator"].startswith("pkg:cargo/ring@")
    assert len(ring["checksums"][0]["checksumValue"]) == 64
    depends = {item["relatedSpdxElement"] for item in document["relationships"] if item["relationshipType"] == "DEPENDS_ON"}
    assert ring["SPDXID"] in depends
    # The path dependency is a file of the archive, not a package.
    assert "pc_common" not in {item["name"] for item in document["packages"]}

    # Still three files in SHA256SUMS, and --verify re-checks the recorded binaries.
    assert len(built.checksums.read_text().splitlines()) == 3
    assert verify_release(tmp_path / "dist").archive_sha256 == built.archive_sha256
    assert verify_archive_binaries(built.archive) == identity["binaries"]


def test_two_builds_from_the_same_binaries_are_byte_identical(tmp_path, no_docker):
    source = checkout_with_host_crates(tmp_path)
    first = build(tmp_path, "one", source, binaries_from=fake_build(tmp_path / "bin-a", {PROBE: b"probe"}))
    second = build(tmp_path, "two", source, binaries_from=fake_build(tmp_path / "bin-b", {PROBE: b"probe"}))
    assert sha256(first.archive) == sha256(second.archive)
    assert first.sbom_bytes == second.sbom_bytes
    other = build(tmp_path, "three", source, binaries_from=fake_build(tmp_path / "bin-c", {PROBE: b"other"}))
    assert sha256(other.archive) != sha256(first.archive)


@pytest.mark.parametrize(
    ("damage", "message"),
    [
        ("tamper", "does not match host-binaries.sha256"),
        ("missing", "is missing from"),
        ("extra", "which is not a host binary of this tree"),
        ("symlink", "not a regular file"),
        ("image", "not the pinned"),
        ("no-list", "is not a host binary build"),
    ],
)
def test_binaries_from_refuses_anything_but_the_recorded_bytes(tmp_path, no_docker, damage, message):
    source = checkout_with_host_crates(tmp_path)
    directory = fake_build(
        tmp_path / "bin", {PROBE: b"probe"}, image="rust:1.99-alpine@sha256:" + "0" * 64 if damage == "image" else None
    )
    if damage == "tamper":
        (directory / PROBE).write_bytes(b"probe, changed")
    elif damage == "missing":
        fake_build(directory, {})
        (directory / PROBE).unlink()
    elif damage == "extra":
        fake_build(directory, {PROBE: b"probe", "version_agent/bin/linux-amd64/proxy-control-version-agent": b"x"})
    elif damage == "symlink":
        (directory / PROBE).unlink()
        (directory / PROBE).symlink_to("/dev/null")
    elif damage == "no-list":
        (directory / HOST_BINARY_DIGESTS).unlink()
    with pytest.raises(ReleaseBuildError, match=message):
        build(tmp_path, "dist", source, binaries_from=directory)
    assert not (tmp_path / "dist").exists()


def test_no_binaries_leaves_them_out_without_running_the_builder(tmp_path, no_docker):
    source = checkout_with_host_crates(tmp_path)
    built = build(tmp_path, "dist", source, binaries=False)
    assert f"proxy-control/{PROBE}" not in tar_names(built.archive)
    assert "binaries" not in identity_of(built.archive)


def test_binaries_from_and_no_binaries_exclude_each_other(tmp_path, capsys):
    with pytest.raises(SystemExit) as raised:
        release_build.main(["--no-binaries", "--binaries-from", str(tmp_path)])
    assert raised.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
    with pytest.raises(ReleaseBuildError, match="exclude each other"):
        build(tmp_path, "dist", tmp_path, binaries_from=tmp_path, binaries=False)


def test_the_default_build_runs_the_pinned_builder_on_tracked_crates_only(tmp_path, monkeypatch):
    """Without a flag the release builds its binaries itself: no layer cache, amd64, the
    commit epoch, the `binaries` stage exported to a local directory, and a context staged
    from tracked files of VERSION, the list and the listed crates — nothing else."""
    source = checkout_with_host_crates(tmp_path)
    (source / "installer/src/untracked.rs").write_text("// never staged\n")
    seen: dict[str, object] = {}

    def builder(command):
        command = list(command)
        seen["command"] = command
        context = Path(command[-1])
        seen["context"] = sorted(path.relative_to(context).as_posix() for path in context.rglob("*") if path.is_file())
        seen["dockerfile"] = Path(command[command.index("--file") + 1]).read_bytes()
        output = command[command.index("--output") + 1]
        assert output.startswith("type=local,dest=")
        fake_build(Path(output.removeprefix("type=local,dest=")), {PROBE: b"built probe"})

    monkeypatch.setattr(release_build, "_run_builder", builder)
    built = build(tmp_path, "dist", source, require_clean=False)

    command = seen["command"]
    assert command[:3] == ["docker", "buildx", "build"]
    for flag in ("--no-cache", "--platform", "linux/amd64", "--target", "binaries", f"SOURCE_DATE_EPOCH={FIXED_EPOCH}"):
        assert flag in command
    assert seen["dockerfile"] == (ROOT / HOST_BINARIES_DOCKERFILE).read_bytes()
    assert seen["context"] == sorted(
        ["VERSION", HOST_BINARIES_LIST, LIBRARY_FILE, "pc_common/Cargo.toml",
         "installer/Cargo.lock", "installer/Cargo.toml", "installer/src/main.rs"]
    )
    assert archive_member(built.archive, PROBE) == (0o755, b"built probe")


def test_build_binaries_only_prints_the_digest_of_each(tmp_path, monkeypatch, capsys):
    source = checkout_with_host_crates(tmp_path)

    def builder(command):
        output = list(command)[list(command).index("--output") + 1]
        fake_build(Path(output.removeprefix("type=local,dest=")), {PROBE: b"probe"})

    monkeypatch.setattr(release_build, "_run_builder", builder)
    assert release_build.main(["--source", str(source), "--build-binaries", str(tmp_path / "bin")]) == 0
    assert capsys.readouterr().out == f"{hashlib.sha256(b'probe').hexdigest()}  {PROBE}\n"
    # A second build never lands on top of an earlier one.
    assert release_build.main(["--source", str(source), "--build-binaries", str(tmp_path / "bin")]) == 1
    assert "must be empty" in capsys.readouterr().err


def test_a_tracked_host_binary_is_refused(tmp_path):
    source = checkout_with_host_crates(tmp_path)
    (source / PROBE).parent.mkdir(parents=True)
    (source / PROBE).write_bytes(b"committed by mistake")
    git(source, "add", "-f", PROBE)
    git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "oops")
    with pytest.raises(ReleaseBuildError, match="must not be tracked"):
        host_crates(source, tracked_files(source))


def test_a_host_crate_from_outside_crates_io_is_refused(tmp_path, no_docker):
    source = checkout_with_host_crates(tmp_path)
    lock = source / "installer/Cargo.lock"
    lock.write_text(lock.read_text() + '\n[[package]]\nname = "forked"\nversion = "1.0.0"\n'
                    'source = "git+https://example.invalid/forked#0123"\n')
    git(source, "commit", "-qam", "git dependency")
    with pytest.raises(ReleaseBuildError, match="without a crates.io checksum"):
        build(tmp_path, "dist", source, binaries_from=fake_build(tmp_path / "bin", {PROBE: b"probe"}))


def test_verify_refuses_an_archive_whose_binary_differs_from_its_identity(tmp_path, no_docker):
    source = checkout_with_host_crates(tmp_path)
    built = build(tmp_path, "dist", source, binaries_from=fake_build(tmp_path / "bin", {PROBE: b"probe"}))
    with tarfile.open(built.archive, mode="r:gz") as handle:
        members = []
        for member in handle.getmembers():
            stream = handle.extractfile(member)
            assert stream is not None
            members.append((member, stream.read()))
    forged = tmp_path / "forged.tar.gz"
    with tarfile.open(forged, mode="w:gz") as handle:
        for member, data in members:
            if member.name == f"proxy-control/{PROBE}":
                data = b"swapped"
                member.size = len(data)
            handle.addfile(member, io.BytesIO(data))
    with pytest.raises(ReleaseBuildError, match="does not match release/release.json"):
        verify_archive_binaries(forged)


def test_the_repository_ignores_prebuilt_host_binaries():
    for crate, binary in (("installer", "proxy-control-installer"),
                          ("version_agent", "proxy-control-version-agent")):
        completed = subprocess.run(
            ("git", "-C", str(ROOT), "check-ignore", "-q", f"{crate}/bin/linux-amd64/{binary}"),
            capture_output=True,
        )
        assert completed.returncode == 0, crate


def test_the_knowledge_graph_is_tracked_but_never_shipped(tmp_path):
    """`graphify-out/` lives in the repository for agents; a release archive leaves it out."""
    import subprocess

    from release.build import tracked_files

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "graphify-out").mkdir()
    (tmp_path / "graphify-out" / "graph.json").write_text("{}")
    (tmp_path / "VERSION").write_text("1.1.0\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    assert tracked_files(tmp_path) == ("VERSION",)
