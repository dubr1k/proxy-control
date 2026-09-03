from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any

import pytest

import installer.release as release_module
from installer.release import (
    ArchiveEntry,
    ArchiveManifest,
    ReleaseError,
    ReleaseManifest,
    safe_extract_tar as _safe_extract_tar,
    verify_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
VALID_MANIFEST = ROOT / "tests/fixtures/releases/valid-manifest.json"
RELEASE_MANIFEST = ROOT / "release/external-artifacts.json"


def _manifest_data() -> dict[str, Any]:
    return json.loads(VALID_MANIFEST.read_text(encoding="utf-8"))


def _manifest_bytes(mutator) -> bytes:
    data = _manifest_data()
    mutator(data)
    return json.dumps(data).encode()


def _tar(
    tmp_path: Path,
    members: list[dict[str, Any]],
    *,
    filename: str = "artifact.tar.gz",
) -> Path:
    path = tmp_path / filename
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            info = tarfile.TarInfo(member["name"])
            info.type = member.get("type", tarfile.REGTYPE)
            info.mode = member.get("mode", 0o644)
            info.uid = member.get("uid", 43210)
            info.gid = member.get("gid", 43210)
            info.linkname = member.get("linkname", "")
            data = member.get("data", b"")
            if info.isreg():
                info.size = member.get("size", len(data))
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    return path


def _valid_members() -> list[dict[str, Any]]:
    return [
        {"name": "pkg", "type": tarfile.DIRTYPE, "mode": 0o755},
        {"name": "pkg/app", "data": b"verified payload\n", "mode": 0o755},
        {
            "name": "pkg/current",
            "type": tarfile.SYMTYPE,
            "linkname": "app",
            "mode": 0o777,
        },
    ]


def _valid_archive_manifest(
    *, max_entries: int = 16, max_total_size: int = 1024
) -> ArchiveManifest:
    return ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(
            ArchiveEntry(path="pkg", kind="directory", mode=0o755),
            ArchiveEntry(
                path="pkg/app",
                kind="file",
                mode=0o755,
                sha256=hashlib.sha256(b"verified payload\n").hexdigest(),
            ),
            ArchiveEntry(
                path="pkg/current",
                kind="symlink",
                mode=0o777,
                link_target="app",
            ),
        ),
        max_entries=max_entries,
        max_total_size=max_total_size,
    )


def safe_extract_tar(
    archive: Path,
    destination: Path,
    manifest: ArchiveManifest,
) -> None:
    if manifest.archive_sha256 == "0" * 64:
        manifest = replace(
            manifest,
            archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
    _safe_extract_tar(archive, destination, manifest)


def _stage_paths(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.stage-*"))


def test_reviewed_manifest_and_fixture_are_identical_and_strictly_valid():
    assert RELEASE_MANIFEST.read_bytes() == VALID_MANIFEST.read_bytes()
    manifest = ReleaseManifest.from_bytes(VALID_MANIFEST.read_bytes())
    assert manifest.schema_version == 1


def test_external_artifact_is_arch_specific_and_version_pinned():
    manifest = ReleaseManifest.from_bytes(VALID_MANIFEST.read_bytes())

    arm64 = manifest.external_artifact("three_xui", "arm64")
    amd64 = manifest.artifacts.for_platform("three_xui", "amd64")

    assert arm64.version == "3.7.0"
    assert arm64.tag == "v3.7.0"
    assert arm64.sha256 == (
        "3caf1db1e8b10bb1fa1324c945522690bcf01c533ee75b377268f1c01a3ce896"
    )
    assert arm64.url == (
        "https://github.com/MHSanaei/3x-ui/releases/download/"
        "v3.7.0/x-ui-linux-arm64.tar.gz"
    )
    assert arm64.architecture == "arm64"
    assert arm64.spdx_license == "GPL-3.0-only"
    assert amd64.sha256 == (
        "0f8dd7baef3458f6591574e24814f322cf7f5e1e27f0a594683745e50be84ec5"
    )
    assert "latest" not in arm64.url.lower()
    with pytest.raises(FrozenInstanceError):
        arm64.version = "latest"  # type: ignore[misc]


def test_mita_pins_include_package_and_executable_hashes_for_both_architectures():
    manifest = ReleaseManifest.from_bytes(VALID_MANIFEST.read_bytes())
    expected = {
        "amd64": (
            "44622bea7fac732984ac6cf1189e555fd9add1969001e9b2d7cdea9416b5919a",
            "38835a88e9b7fb09de0a3b6b5110e3a98719bffd9471aa07ddb7e03dc678a170",
        ),
        "arm64": (
            "a43dbc4d75dcb18978ea79b924ce859e2485af8b776dfc981b29a7b60644157c",
            "5105cf47ae85cfa885922fe8384f53f1977ea230259eb066130b7232ce0847b0",
        ),
    }

    for arch, (package_hash, executable_hash) in expected.items():
        pin = manifest.external_artifact("mita", arch)
        assert pin.version == "3.36.0"
        assert pin.sha256 == package_hash
        assert pin.executable_path == "usr/bin/mita"
        assert pin.executable_sha256 == executable_hash
        assert pin.spdx_license == "GPL-3.0-or-later"
        assert pin.url.endswith(f"mita_3.36.0_{arch}.deb")
        assert "/download/v3.36.0/" in pin.url


@pytest.mark.parametrize(
    ("description", "mutator", "match"),
    [
        (
            "root unknown key",
            lambda data: data.update({"unexpected": True}),
            "unknown manifest key",
        ),
        (
            "artifact unknown key",
            lambda data: data["artifacts"][0].update({"unexpected": True}),
            "unknown artifact key",
        ),
        (
            "pin unknown key",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"unexpected": True}
            ),
            "unknown platform key",
        ),
        (
            "unsupported schema",
            lambda data: data.update({"schema_version": 2}),
            "schema_version",
        ),
        (
            "uppercase digest",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"sha256": "A" * 64}
            ),
            "lowercase SHA-256",
        ),
        (
            "http URL",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "http://github.com/enfein/mieru/releases/download/"
                "v3.36.0/mita_3.36.0_amd64.deb"}
            ),
            "HTTPS",
        ),
        (
            "wrong host",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "https://example.com/enfein/mieru/releases/download/"
                "v3.36.0/mita_3.36.0_amd64.deb"}
            ),
            "GitHub host",
        ),
        (
            "mutable latest URL",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "https://github.com/enfein/mieru/releases/latest/"
                "download/mita_3.36.0_amd64.deb"}
            ),
            "immutable release URL",
        ),
        (
            "URL query",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "https://github.com/enfein/mieru/releases/download/"
                "v3.36.0/mita_3.36.0_amd64.deb?raw=1"}
            ),
            "query or fragment",
        ),
        (
            "tag version mismatch",
            lambda data: data["artifacts"][0].update({"tag": "v3.35.0"}),
            "tag must equal",
        ),
        (
            "URL repository mismatch",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "https://github.com/attacker/mieru/releases/download/"
                "v3.36.0/mita_3.36.0_amd64.deb"}
            ),
            "repository",
        ),
        (
            "platform mismatch",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"architecture": "arm64"}
            ),
            "platform mismatch",
        ),
        (
            "filename architecture mismatch",
            lambda data: data["artifacts"][0]["platforms"]["amd64"].update(
                {"url": "https://github.com/enfein/mieru/releases/download/"
                "v3.36.0/mita_3.36.0_arm64.deb"}
            ),
            "architecture",
        ),
        (
            "unsupported SPDX",
            lambda data: data["artifacts"][0].update({"spdx_license": "GPLv3+"}),
            "SPDX",
        ),
        (
            "missing platform",
            lambda data: data["artifacts"][0]["platforms"].pop("arm64"),
            "platforms must be exactly",
        ),
    ],
)
def test_manifest_rejects_invalid_schema(description, mutator, match):
    del description
    with pytest.raises(ReleaseError, match=match):
        ReleaseManifest.from_bytes(_manifest_bytes(mutator))


def test_manifest_rejects_duplicate_json_keys_and_artifact_names():
    duplicate_key = VALID_MANIFEST.read_bytes().replace(
        b'"schema_version": 1,',
        b'"schema_version": 1, "schema_version": 1,',
        1,
    )
    with pytest.raises(ReleaseError, match="duplicate JSON key"):
        ReleaseManifest.from_bytes(duplicate_key)

    duplicate_artifact = _manifest_bytes(
        lambda data: data["artifacts"].append(data["artifacts"][0])
    )
    with pytest.raises(ReleaseError, match="duplicate artifact"):
        ReleaseManifest.from_bytes(duplicate_artifact)


def test_manifest_lookup_rejects_unknown_artifact_and_architecture():
    manifest = ReleaseManifest.from_bytes(VALID_MANIFEST.read_bytes())
    with pytest.raises(ReleaseError, match="unknown artifact"):
        manifest.external_artifact("unknown", "amd64")
    with pytest.raises(ReleaseError, match="unsupported architecture"):
        manifest.external_artifact("mita", "386")


def test_verify_artifact_streams_and_compares_an_exact_lowercase_digest(tmp_path):
    artifact = tmp_path / "large.bin"
    artifact.write_bytes((b"0123456789abcdef" * 200_000) + b"tail")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    verify_artifact(artifact, digest)

    with pytest.raises(ReleaseError, match="digest mismatch"):
        verify_artifact(artifact, "0" * 64)
    with pytest.raises(ReleaseError, match="lowercase SHA-256"):
        verify_artifact(artifact, digest.upper())
    with pytest.raises(ReleaseError, match="regular file"):
        verify_artifact(tmp_path / "missing", digest)


@pytest.mark.parametrize("member", ["/etc/shadow", "../../root/.ssh", "safe/../escape"])
def test_safe_extract_rejects_escaping_member(tmp_path, member):
    archive = _tar(tmp_path, [{"name": member, "data": b"hostile"}])
    destination = tmp_path / "stage"
    manifest = ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(ArchiveEntry(path="safe", kind="file"),),
        max_entries=4,
        max_total_size=1024,
    )

    with pytest.raises(ReleaseError, match="unsafe archive path"):
        safe_extract_tar(archive, destination, manifest)

    assert not destination.exists()
    assert _stage_paths(destination) == []


@pytest.mark.parametrize("member", [r"..\\escape", r"safe\\..\\escape"])
def test_safe_extract_rejects_backslash_member_paths(tmp_path, member):
    archive = _tar(tmp_path, [{"name": member, "data": b"hostile"}])
    with pytest.raises(ReleaseError, match="unsafe archive path"):
        safe_extract_tar(archive, tmp_path / "stage", _valid_archive_manifest())


@pytest.mark.parametrize("target", ["/etc/shadow", "../../outside"])
def test_safe_extract_rejects_escaping_symlink_target(tmp_path, target):
    members = _valid_members()
    members[-1]["linkname"] = target
    archive = _tar(tmp_path, members)
    destination = tmp_path / "stage"

    with pytest.raises(ReleaseError, match="unsafe symlink target"):
        safe_extract_tar(archive, destination, _valid_archive_manifest())

    assert not destination.exists()
    assert _stage_paths(destination) == []


@pytest.mark.parametrize(
    "entry_type",
    [tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, b"s"],
)
def test_safe_extract_rejects_hardlinks_and_special_files(tmp_path, entry_type):
    member = {"name": "pkg/app", "type": entry_type, "linkname": "target"}
    archive = _tar(tmp_path, [member])
    manifest = ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(ArchiveEntry(path="pkg/app", kind="file"),),
        max_entries=2,
        max_total_size=1024,
    )

    with pytest.raises(ReleaseError, match="unsupported archive entry type"):
        safe_extract_tar(archive, tmp_path / "stage", manifest)


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o6755])
def test_safe_extract_rejects_setuid_and_setgid_modes(tmp_path, mode):
    archive = _tar(tmp_path, [{"name": "pkg/app", "data": b"x", "mode": mode}])
    manifest = ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(ArchiveEntry(path="pkg/app", kind="file"),),
        max_entries=2,
        max_total_size=1024,
    )

    with pytest.raises(ReleaseError, match="setuid or setgid"):
        safe_extract_tar(archive, tmp_path / "stage", manifest)


@pytest.mark.parametrize(
    ("members", "manifest", "match"),
    [
        (
            [
                {"name": "pkg/app", "data": b"one"},
                {"name": "./pkg/app", "data": b"two"},
            ],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(ArchiveEntry(path="pkg/app", kind="file"),),
                max_entries=4,
                max_total_size=1024,
            ),
            "duplicate normalized archive path",
        ),
        (
            [
                {"name": "pkg/app", "data": b"x"},
                {"name": "pkg/extra", "data": b"x"},
            ],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(ArchiveEntry(path="pkg/app", kind="file"),),
                max_entries=4,
                max_total_size=1024,
            ),
            "unexpected archive entry",
        ),
        (
            [{"name": "pkg/app", "data": b"x"}],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(
                    ArchiveEntry(path="pkg/app", kind="file"),
                    ArchiveEntry(path="pkg/required", kind="file"),
                ),
                max_entries=4,
                max_total_size=1024,
            ),
            "missing archive entry",
        ),
        (
            [{"name": "pkg/app", "type": tarfile.DIRTYPE}],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(ArchiveEntry(path="pkg/app", kind="file"),),
                max_entries=4,
                max_total_size=1024,
            ),
            "archive entry type mismatch",
        ),
        (
            [{"name": "pkg/app", "data": b"0123456789"}],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(ArchiveEntry(path="pkg/app", kind="file"),),
                max_entries=4,
                max_total_size=4,
            ),
            "archive size limit",
        ),
        (
            [
                {"name": "pkg/a", "data": b"a"},
                {"name": "pkg/b", "data": b"b"},
            ],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(
                    ArchiveEntry(path="pkg/a", kind="file"),
                    ArchiveEntry(path="pkg/b", kind="file"),
                ),
                max_entries=1,
                max_total_size=1024,
            ),
            "archive entry count limit",
        ),
        (
            [
                {"name": "pkg/link", "type": tarfile.SYMTYPE, "linkname": "app"},
                {"name": "pkg/link/child", "data": b"hostile"},
            ],
            ArchiveManifest(
                archive_sha256="0" * 64,
                entries=(
                    ArchiveEntry(
                        path="pkg/link", kind="symlink", link_target="app"
                    ),
                    ArchiveEntry(path="pkg/link/child", kind="file"),
                ),
                max_entries=4,
                max_total_size=1024,
            ),
            "non-directory parent",
        ),
    ],
)
def test_safe_extract_rejects_invalid_layout(tmp_path, members, manifest, match):
    archive = _tar(tmp_path, members)
    destination = tmp_path / "stage"

    with pytest.raises(ReleaseError, match=match):
        safe_extract_tar(archive, destination, manifest)

    assert not destination.exists()
    assert _stage_paths(destination) == []


def test_safe_extract_rejects_manifest_content_and_mode_mismatch(tmp_path):
    archive = _tar(tmp_path, _valid_members())
    wrong_digest = ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(
            ArchiveEntry(path="pkg", kind="directory", mode=0o755),
            ArchiveEntry(path="pkg/app", kind="file", mode=0o644, sha256="0" * 64),
            ArchiveEntry(
                path="pkg/current",
                kind="symlink",
                mode=0o777,
                link_target="app",
            ),
        ),
        max_entries=16,
        max_total_size=1024,
    )

    with pytest.raises(ReleaseError, match="archive entry mode mismatch"):
        safe_extract_tar(archive, tmp_path / "stage", wrong_digest)

    wrong_digest = ArchiveManifest(
        archive_sha256="0" * 64,
        entries=(
            ArchiveEntry(path="pkg", kind="directory", mode=0o755),
            ArchiveEntry(path="pkg/app", kind="file", mode=0o755, sha256="0" * 64),
            ArchiveEntry(
                path="pkg/current",
                kind="symlink",
                mode=0o777,
                link_target="app",
            ),
        ),
        max_entries=16,
        max_total_size=1024,
    )
    with pytest.raises(ReleaseError, match="archive member digest mismatch"):
        safe_extract_tar(archive, tmp_path / "stage", wrong_digest)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_safe_extract_rejects_symlinked_destination_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)
    archive = _tar(tmp_path, _valid_members())

    with pytest.raises(ReleaseError, match="destination parent.*symlink"):
        safe_extract_tar(
            archive,
            linked_parent / "stage",
            _valid_archive_manifest(),
        )

    assert list(outside.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_safe_extract_rejects_preexisting_destination_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_text("trusted", encoding="utf-8")
    destination = tmp_path / "stage"
    destination.symlink_to(outside, target_is_directory=True)
    archive = _tar(tmp_path, _valid_members())

    with pytest.raises(ReleaseError, match="destination must not be a symlink"):
        safe_extract_tar(archive, destination, _valid_archive_manifest())

    assert marker.read_text(encoding="utf-8") == "trusted"
    assert destination.is_symlink()
    assert _stage_paths(destination) == []


def test_validation_failure_preserves_existing_destination_without_partial_tree(
    tmp_path,
):
    destination = tmp_path / "stage"
    destination.mkdir()
    marker = destination / "trusted"
    marker.write_text("old tree", encoding="utf-8")
    archive = _tar(tmp_path, [{"name": "unexpected", "data": b"hostile"}])

    with pytest.raises(ReleaseError, match="unexpected archive entry"):
        safe_extract_tar(archive, destination, _valid_archive_manifest())

    assert marker.read_text(encoding="utf-8") == "old tree"
    assert sorted(path.name for path in destination.iterdir()) == ["trusted"]
    assert _stage_paths(destination) == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_valid_extraction_replaces_preexisting_hostile_entries_without_following_them(
    tmp_path,
):
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_marker = outside / "marker"
    outside_marker.write_text("outside", encoding="utf-8")
    destination = tmp_path / "stage"
    destination.mkdir()
    (destination / "pkg").symlink_to(outside, target_is_directory=True)
    archive = _tar(tmp_path, _valid_members())

    safe_extract_tar(archive, destination, _valid_archive_manifest())

    assert outside_marker.read_text(encoding="utf-8") == "outside"
    assert (destination / "pkg/app").read_bytes() == b"verified payload\n"
    assert (destination / "pkg/current").is_symlink()
    assert os.readlink(destination / "pkg/current") == "app"
    assert (destination / "pkg/current").read_bytes() == b"verified payload\n"
    assert (destination / "pkg/app").stat().st_uid == os.getuid()
    assert (destination / "pkg/app").stat().st_gid != 43210
    assert _stage_paths(destination) == []


def test_extraction_failure_cleans_stage_and_preserves_existing_destination(
    tmp_path, monkeypatch
):
    destination = tmp_path / "stage"
    destination.mkdir()
    marker = destination / "trusted"
    marker.write_text("old tree", encoding="utf-8")
    archive = _tar(tmp_path, _valid_members())

    def fail_copy(*_args, **_kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr(release_module, "_copy_regular_member", fail_copy)

    with pytest.raises(ReleaseError, match="could not extract archive"):
        safe_extract_tar(archive, destination, _valid_archive_manifest())

    assert marker.read_text(encoding="utf-8") == "old tree"
    assert _stage_paths(destination) == []


def test_release_verify_cli_validates_fixture_manifest():
    completed = subprocess.run(
        [
            sys.executable,
            "release/verify.py",
            "manifest",
            "tests/fixtures/releases/valid-manifest.json",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": "."},
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "manifest: ok\n"


def test_archive_path_swap_cannot_change_verified_bytes(tmp_path, monkeypatch):
    archive = _tar(
        tmp_path,
        [{"name": "pkg/app", "data": b"reviewed"}],
        filename="reviewed.tar.gz",
    )
    replacement = _tar(
        tmp_path,
        [{"name": "pkg/app", "data": b"substituted"}],
        filename="substituted.tar.gz",
    )
    manifest = ArchiveManifest(
        entries=(ArchiveEntry(path="pkg/app", kind="file"),),
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_entries=4,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=1024,
    )
    destination = tmp_path / "stage"
    real_verify_open_archive = release_module._verify_open_archive
    swapped = False

    def swap_after_verification(source, expected_sha256, archive_path):
        nonlocal swapped
        real_verify_open_archive(source, expected_sha256, archive_path)
        os.replace(replacement, archive)
        swapped = True

    monkeypatch.setattr(
        release_module,
        "_verify_open_archive",
        swap_after_verification,
    )

    safe_extract_tar(archive, destination, manifest)

    assert swapped
    assert (destination / "pkg/app").read_bytes() == b"reviewed"


def test_archive_digest_is_verified_before_tar_processing(tmp_path):
    archive = _tar(tmp_path, [{"name": "pkg/app", "data": b"payload"}])
    manifest = ArchiveManifest(
        entries=(ArchiveEntry(path="pkg/app", kind="file"),),
        archive_sha256="0" * 64,
        max_entries=4,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=1024,
    )
    destination = tmp_path / "stage"

    with pytest.raises(ReleaseError, match="archive digest mismatch"):
        release_module.safe_extract_tar(archive, destination, manifest)

    assert not destination.exists()


def test_destination_parent_swap_is_detected_at_mutation_boundary(
    tmp_path, monkeypatch
):
    archive = _tar(tmp_path, _valid_members())
    parent = tmp_path / "parent"
    parent.mkdir()
    destination = parent / "stage"
    displaced = tmp_path / "displaced-parent"
    outside = tmp_path / "outside"
    outside.mkdir()
    manifest = ArchiveManifest(
        entries=_valid_archive_manifest().entries,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_entries=16,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=1024,
    )
    real_validate_destination = release_module._validate_destination

    def swap_after_validation(path):
        anchor = real_validate_destination(path)
        parent.rename(displaced)
        parent.symlink_to(outside, target_is_directory=True)
        return anchor

    monkeypatch.setattr(
        release_module,
        "_validate_destination",
        swap_after_validation,
    )

    with pytest.raises(ReleaseError, match="destination parent changed"):
        safe_extract_tar(archive, destination, manifest)

    assert list(outside.iterdir()) == []
    assert list(displaced.iterdir()) == []


def test_decompressed_tar_and_extension_metadata_are_bounded(tmp_path):
    large_payload = _tar(
        tmp_path,
        [{"name": "pkg/app", "data": b"x" * 4096}],
        filename="large.tar.gz",
    )
    large_manifest = ArchiveManifest(
        entries=(ArchiveEntry(path="pkg/app", kind="file"),),
        archive_sha256=hashlib.sha256(large_payload.read_bytes()).hexdigest(),
        max_entries=4,
        max_total_size=8192,
        max_decompressed_size=1024,
        max_metadata_size=128,
    )
    with pytest.raises(ReleaseError, match="decompressed archive size limit"):
        safe_extract_tar(large_payload, tmp_path / "large-stage", large_manifest)

    long_name = f"pkg/{'a' * 600}"
    extension_bomb = _tar(
        tmp_path,
        [{"name": long_name, "data": b"x"}],
        filename="extension.tar.gz",
    )
    extension_manifest = ArchiveManifest(
        entries=(ArchiveEntry(path=long_name, kind="file"),),
        archive_sha256=hashlib.sha256(extension_bomb.read_bytes()).hexdigest(),
        max_entries=4,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=128,
    )
    with pytest.raises(ReleaseError, match="tar metadata limit"):
        safe_extract_tar(
            extension_bomb,
            tmp_path / "extension-stage",
            extension_manifest,
        )


def test_payload_bearing_nonregular_tar_entry_is_rejected(tmp_path):
    archive = tmp_path / "payload-directory.tar.gz"
    with tarfile.open(archive, "w:gz") as opened:
        info = tarfile.TarInfo("pkg")
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.size = 4
        opened.addfile(info, io.BytesIO(b"data"))
    manifest = ArchiveManifest(
        entries=(ArchiveEntry(path="pkg", kind="directory", mode=0o755),),
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_entries=4,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=1024,
    )

    with pytest.raises(ReleaseError, match="payload-bearing non-regular"):
        safe_extract_tar(archive, tmp_path / "stage", manifest)


@pytest.mark.parametrize(
    "url",
    [
        " https://github.com/enfein/mieru/releases/download/"
        "v3.36.0/mita_3.36.0_amd64.deb",
        "https://github.com/enfein/mieru/releases/download/"
        "v3.36.0/mita_3.36.0_amd64.deb ",
        "https://github.com/enfein/mieru/releases/download/"
        "v3.36.0/mita_3.36.0_amd64.deb\n",
        "HTTPS://github.com/enfein/mieru/releases/download/"
        "v3.36.0/mita_3.36.0_amd64.deb",
    ],
)
def test_manifest_rejects_noncanonical_or_control_bearing_url(url):
    data = _manifest_bytes(
        lambda document: document["artifacts"][0]["platforms"]["amd64"].update(
            {"url": url}
        )
    )

    with pytest.raises(ReleaseError, match="canonical|whitespace|control"):
        ReleaseManifest.from_bytes(data)


def test_backup_cleanup_failure_does_not_report_failed_install(tmp_path, monkeypatch):
    archive = _tar(tmp_path, _valid_members())
    manifest = ArchiveManifest(
        entries=_valid_archive_manifest().entries,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        max_entries=16,
        max_total_size=1024,
        max_decompressed_size=32 * 1024,
        max_metadata_size=1024,
    )
    destination = tmp_path / "stage"
    destination.mkdir()
    (destination / "old").write_text("trusted old tree", encoding="utf-8")
    real_remove_tree_at = release_module._remove_tree_at

    def fail_backup_cleanup(parent_fd, name):
        if ".backup-" in name:
            raise OSError("simulated post-commit cleanup failure")
        return real_remove_tree_at(parent_fd, name)

    monkeypatch.setattr(release_module, "_remove_tree_at", fail_backup_cleanup)

    safe_extract_tar(archive, destination, manifest)

    assert (destination / "pkg/app").read_bytes() == b"verified payload\n"
    assert len(list(tmp_path.glob(".stage.backup-*"))) == 1
