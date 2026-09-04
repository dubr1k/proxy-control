#!/usr/bin/env python3
"""Build one reproducible Proxy Control release from tracked files only.

Two builds of the same commit produce byte-identical outputs: the archive is
assembled from `git ls-files -z` in sorted order, every member is owned by
`root:root` with uid/gid zero, the mode comes from the Git executable bit
alone, and every mtime is the release commit timestamp.  Untracked, ignored,
private, and lab state never enters the archive.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

RELEASE_SCHEMA = 1
ARCHIVE_PREFIX = "proxy-control"
IDENTITY_NAME = "release/release.json"
MANIFEST_NAME = "release-manifest.json"
SBOM_NAME = "sbom.spdx.json"
CHECKSUM_NAME = "SHA256SUMS"

# Top-level names that must never reach a release, even if someone tracks one
# of them by accident.
FORBIDDEN_TOP_LEVEL = frozenset(
    {
        ".env",
        ".git",
        ".lab-state",
        ".venv",
        ".worktrees",
        "dist",
        "lab-results",
        "secrets",
    }
)
FORBIDDEN_SUFFIXES = (".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm")

_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseBuildError(RuntimeError):
    """The release cannot be built reproducibly from this source tree."""


@dataclass(frozen=True)
class BuiltRelease:
    """Everything one release build produced, plus its digests."""

    archive: Path
    checksums: Path
    manifest: Path
    sbom: Path
    version: str
    commit: str
    archive_sha256: str
    manifest_bytes: bytes
    sbom_bytes: bytes


def _git(source: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(source), *arguments),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReleaseBuildError(f"git {' '.join(arguments)} failed") from exc
    return completed.stdout


def tracked_files(source: Path) -> tuple[str, ...]:
    """Every tracked path, sorted, with the forbidden ones refused."""
    raw = _git(source, "ls-files", "-z")
    names = tuple(sorted(name for name in raw.split("\0") if name))
    if not names:
        raise ReleaseBuildError("the source tree tracks no files")
    for name in names:
        top = name.split("/", 1)[0]
        if top in FORBIDDEN_TOP_LEVEL:
            raise ReleaseBuildError(f"a release must not contain {top}")
        if name.endswith(FORBIDDEN_SUFFIXES):
            raise ReleaseBuildError(f"a release must not contain {name}")
    return names


def assert_clean(source: Path) -> None:
    """A release is built from a committed tree, never from a dirty index."""
    status = _git(source, "status", "--porcelain")
    dirty = [line for line in status.splitlines() if line.strip()]
    if dirty:
        raise ReleaseBuildError(
            f"refusing to build a release from a dirty tree ({len(dirty)} paths)"
        )


def commit_epoch(source: Path, commit: str) -> int:
    value = _git(source, "show", "-s", "--format=%ct", commit).strip()
    try:
        return int(value)
    except ValueError as exc:
        raise ReleaseBuildError("the release commit has no timestamp") from exc


def _executable(source: Path, name: str) -> bool:
    mode = _git(source, "ls-files", "-s", "--", name).split(maxsplit=1)[0]
    return mode == "100755"


def _member(name: str, size: int, *, epoch: int, executable: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(f"{ARCHIVE_PREFIX}/{name}")
    info.size = size
    info.mtime = epoch
    info.mode = 0o755 if executable else 0o644
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.type = tarfile.REGTYPE
    return info


def _identity_document(
    *,
    version: str,
    commit: str,
    manifest_sha256: str,
    components: Mapping[str, str],
    artifacts: Mapping[str, str],
) -> dict[str, object]:
    return {
        "artifacts": dict(sorted(artifacts.items())),
        "commit": commit,
        "components": dict(sorted(components.items())),
        "manifest_sha256": manifest_sha256,
        "schema": RELEASE_SCHEMA,
        "tag": f"v{version}",
        "version": version,
    }


def _canonical(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def _external_artifacts(source: Path) -> tuple[dict[str, str], dict[str, str]]:
    path = source / "release" / "external-artifacts.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleaseBuildError("the external artifact manifest is unreadable") from exc
    components: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    for entry in document.get("artifacts", []):
        if not isinstance(entry, Mapping):
            continue
        name = str(entry.get("name", ""))
        components[name] = str(entry.get("version", ""))
        for architecture, pin in sorted(entry.get("platforms", {}).items()):
            if isinstance(pin, Mapping) and isinstance(pin.get("sha256"), str):
                artifacts[f"{name}:{architecture}"] = pin["sha256"]
    if not components:
        raise ReleaseBuildError("the external artifact manifest pins nothing")
    return components, artifacts


def build_release(
    output: Path,
    *,
    source: Path,
    version: str,
    commit: str | None = None,
    epoch: int | None = None,
    require_clean: bool = True,
) -> BuiltRelease:
    """Build the archive, checksums, manifest, and SBOM into `output`."""
    if _VERSION_RE.fullmatch(version) is None:
        raise ReleaseBuildError("the release version must be semantic")
    source = Path(source)
    if require_clean:
        assert_clean(source)
    resolved = (commit or _git(source, "rev-parse", "HEAD").strip()).lower()
    if _COMMIT_RE.fullmatch(resolved) is None:
        raise ReleaseBuildError("the release commit must be a full SHA-1")
    declared = (source / "VERSION").read_text(encoding="utf-8").strip()
    if declared != version:
        raise ReleaseBuildError(
            f"VERSION declares {declared!r} but the build asked for {version!r}"
        )
    timestamp = epoch if epoch is not None else commit_epoch(source, resolved)
    names = tracked_files(source)

    components, artifacts = _external_artifacts(source)
    manifest_source = (source / "release" / "external-artifacts.json").read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_source).hexdigest()
    identity = _canonical(
        _identity_document(
            version=version,
            commit=resolved,
            manifest_sha256=manifest_sha256,
            components=components,
            artifacts=artifacts,
        )
    )

    if __package__:
        from release.sbom import build_sbom
    else:  # running the file directly, without the package on sys.path
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from sbom import build_sbom  # type: ignore[no-redef]

    payloads: dict[str, bytes] = {}
    for name in names:
        if name == IDENTITY_NAME:
            continue
        payloads[name] = (source / name).read_bytes()
    payloads[IDENTITY_NAME] = identity

    sbom = build_sbom(
        version=version,
        commit=resolved,
        files={name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
        external=source / "release" / "external-artifacts.json",
        epoch=timestamp,
    )
    payloads[f"release/{SBOM_NAME}"] = sbom

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{ARCHIVE_PREFIX}-v{version}.tar.gz"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as handle:
        for name in sorted(payloads):
            data = payloads[name]
            executable = name in names and _executable(source, name)
            handle.addfile(
                _member(name, len(data), epoch=timestamp, executable=executable),
                io.BytesIO(data),
            )
    # gzip with mtime=0 so the container adds no non-reproducible header.
    compressed = gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)
    archive.write_bytes(compressed)
    archive_sha256 = hashlib.sha256(compressed).hexdigest()

    manifest_document = {
        "archive": archive.name,
        "archive_sha256": archive_sha256,
        "commit": resolved,
        "external_manifest_sha256": manifest_sha256,
        "file_count": len(payloads),
        "schema": RELEASE_SCHEMA,
        "source_epoch": timestamp,
        "tag": f"v{version}",
        "version": version,
    }
    manifest_bytes = _canonical(manifest_document)
    manifest = output / MANIFEST_NAME
    manifest.write_bytes(manifest_bytes)

    sbom_path = output / SBOM_NAME
    sbom_path.write_bytes(sbom)

    checksums = output / CHECKSUM_NAME
    checksums.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in (archive, manifest, sbom_path)
        )
    )

    return BuiltRelease(
        archive=archive,
        checksums=checksums,
        manifest=manifest,
        sbom=sbom_path,
        version=version,
        commit=resolved,
        archive_sha256=archive_sha256,
        manifest_bytes=manifest_bytes,
        sbom_bytes=sbom,
    )


def verify_release(dist: Path) -> BuiltRelease:
    """Re-check every digest a built release published."""
    dist = Path(dist)
    manifest_bytes = (dist / MANIFEST_NAME).read_bytes()
    manifest = json.loads(manifest_bytes)
    archive = dist / str(manifest["archive"])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != manifest["archive_sha256"]:
        raise ReleaseBuildError("the published archive digest does not match")
    recorded = {}
    for line in (dist / CHECKSUM_NAME).read_text().splitlines():
        value, _, name = line.partition("  ")
        recorded[name] = value
    for path in (archive, dist / MANIFEST_NAME, dist / SBOM_NAME):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if recorded.get(path.name) != actual:
            raise ReleaseBuildError(f"{path.name} does not match {CHECKSUM_NAME}")
    return BuiltRelease(
        archive=archive,
        checksums=dist / CHECKSUM_NAME,
        manifest=dist / MANIFEST_NAME,
        sbom=dist / SBOM_NAME,
        version=str(manifest["version"]),
        commit=str(manifest["commit"]),
        archive_sha256=digest,
        manifest_bytes=manifest_bytes,
        sbom_bytes=(dist / SBOM_NAME).read_bytes(),
    )


def archive_names(archive: Path) -> tuple[str, ...]:
    with tarfile.open(archive, mode="r:gz") as handle:
        return tuple(sorted(handle.getnames()))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--version", required=False)
    parser.add_argument("--commit")
    parser.add_argument("--epoch", type=int)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--verify", type=Path, help="verify a built dist instead")
    arguments = parser.parse_args(argv)
    try:
        if arguments.verify is not None:
            built = verify_release(arguments.verify)
            print(f"verified {built.archive.name} {built.archive_sha256}")
            return 0
        version = arguments.version or (
            (arguments.source / "VERSION").read_text(encoding="utf-8").strip()
        )
        built = build_release(
            arguments.output,
            source=arguments.source,
            version=version,
            commit=arguments.commit,
            epoch=arguments.epoch,
            require_clean=not arguments.allow_dirty,
        )
    except (ReleaseBuildError, OSError, ValueError) as exc:
        print(f"RELEASE FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"{built.archive_sha256}  {built.archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
