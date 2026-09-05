from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from release.build import (
    MANIFEST_NAME,
    SBOM_NAME,
    ReleaseBuildError,
    build_release,
    tracked_files,
    verify_release,
)
from release.sbom import SbomError, build_sbom


ROOT = Path(__file__).parents[1]
FIXED_EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z
VERSION = "0.1.0"


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
    (root / "installer" / "cli.py").write_text("print('cli')\n")
    (root / "README.md").write_text("# release fixture\n")
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
                    }
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


def build(tmp_path: Path, output: str, source: Path, **kwargs) -> object:
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


def test_bootstrap_verifies_before_it_dispatches_through_sudo():
    script = (ROOT / "install-bootstrap").read_text()
    dispatch = script.index("exec sudo")
    for check in (
        "must not be group/other-writable",
        "archive checksum mismatch",
        "the manifest records a different archive digest",
        "stable releases only",
        "unsafe member in the release archive",
    ):
        assert check in script
        assert script.index(check) < dispatch
    assert "run the verification as an unprivileged user" in script
    assert "curl" not in script


def test_release_workflow_pins_actions_and_separates_privileged_jobs():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    for job in (
        "quality:",
        "build-twice-and-compare:",
        "lab-amd64:",
        "lab-arm64:",
        "attest:",
        "draft-release:",
        "publish:",
    ):
        assert job in workflow
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


def test_version_file_matches_the_declared_release():
    assert (ROOT / "VERSION").read_text().strip() == VERSION


def test_the_verify_tool_runs_as_a_script_from_the_repository_root():
    """The release workflow runs `python release/verify.py`, which puts
    `release/` on sys.path and not the repository root."""
    completed = subprocess.run(
        (sys.executable, "release/verify.py", "manifest", "release/external-artifacts.json"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert completed.returncode == 0, completed.stderr
    assert "ok" in completed.stdout
