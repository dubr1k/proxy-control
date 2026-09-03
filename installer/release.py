from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SUPPORTED_ARCHITECTURES = frozenset({"amd64", "arm64"})
_SUPPORTED_SPDX_LICENSES = frozenset({"GPL-3.0-only", "GPL-3.0-or-later"})
_COPY_CHUNK_SIZE = 1024 * 1024


class ReleaseError(ValueError):
    """A release manifest or artifact failed closed validation."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class ArtifactPin:
    name: str
    version: str
    tag: str
    repository: str
    spdx_license: str
    architecture: str
    url: str
    sha256: str
    executable_path: str | None = None
    executable_sha256: str | None = None


@dataclass(frozen=True)
class ExternalArtifact:
    """Immutable artifact registry with exact name and architecture lookup."""

    _pins: Mapping[str, Mapping[str, ArtifactPin]] = field(repr=False)

    @classmethod
    def from_pins(
        cls, pins: Mapping[str, Mapping[str, ArtifactPin]]
    ) -> ExternalArtifact:
        immutable = {
            name: MappingProxyType(dict(platforms))
            for name, platforms in pins.items()
        }
        return cls(MappingProxyType(immutable))

    def for_platform(self, name: str, arch: str) -> ArtifactPin:
        if arch not in _SUPPORTED_ARCHITECTURES:
            raise ReleaseError(f"unsupported architecture: {arch}")
        try:
            artifact = self._pins[name]
        except KeyError as exc:
            raise ReleaseError(f"unknown artifact: {name}") from exc
        try:
            return artifact[arch]
        except KeyError as exc:
            raise ReleaseError(
                f"artifact {name!r} has no pin for architecture {arch!r}"
            ) from exc


@dataclass(frozen=True)
class ReleaseManifest:
    schema_version: int
    artifacts: ExternalArtifact

    @classmethod
    def from_bytes(cls, data: bytes) -> ReleaseManifest:
        document = _load_json(data)
        root = _require_object(document, "manifest")
        _require_keys(root, {"schema_version", "artifacts"}, "manifest")

        schema_version = root["schema_version"]
        if type(schema_version) is not int or schema_version != 1:
            raise ReleaseError("schema_version must be the integer 1")

        raw_artifacts = root["artifacts"]
        if type(raw_artifacts) is not list or not raw_artifacts:
            raise ReleaseError("artifacts must be a non-empty array")

        pins: dict[str, Mapping[str, ArtifactPin]] = {}
        for index, raw_artifact in enumerate(raw_artifacts):
            artifact_name, platforms = _parse_artifact(raw_artifact, index)
            if artifact_name in pins:
                raise ReleaseError(f"duplicate artifact: {artifact_name}")
            pins[artifact_name] = platforms

        return cls(
            schema_version=schema_version,
            artifacts=ExternalArtifact.from_pins(pins),
        )

    def external_artifact(self, name: str, arch: str) -> ArtifactPin:
        return self.artifacts.for_platform(name, arch)


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    kind: str
    mode: int | None = None
    sha256: str | None = None
    link_target: str | None = None


@dataclass(frozen=True)
class ArchiveManifest:
    entries: tuple[ArchiveEntry, ...]
    max_entries: int = 10_000
    max_total_size: int = 1024 * 1024 * 1024


@dataclass(frozen=True)
class _ValidatedMember:
    path: str
    kind: str
    info: tarfile.TarInfo
    expected: ArchiveEntry
    resolved_link_target: str | None = None


def verify_artifact(path: Path, expected_sha256: str) -> None:
    """Stream an artifact once and compare its exact reviewed SHA-256."""

    _require_sha256(expected_sha256, "expected artifact")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"artifact is not a regular file: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"artifact is not a regular file: {path}")

    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(_COPY_CHUNK_SIZE):
                digest.update(chunk)
    except OSError as exc:
        raise ReleaseError(f"could not read artifact: {path}") from exc

    actual = digest.hexdigest()
    if not secrets.compare_digest(actual, expected_sha256):
        raise ReleaseError(
            f"artifact digest mismatch for {path.name}: expected "
            f"{expected_sha256}, got {actual}"
        )


def safe_extract_tar(
    archive: Path,
    destination: Path,
    manifest: ArchiveManifest,
) -> None:
    """Validate an entire tar, then build and atomically install a fresh tree."""

    expected = _validate_archive_manifest(manifest)
    stage: Path | None = None
    try:
        archive_metadata = archive.lstat()
        if not stat.S_ISREG(archive_metadata.st_mode):
            raise ReleaseError(f"archive is not a regular file: {archive}")

        with archive.open("rb") as raw_archive:
            with tarfile.open(fileobj=raw_archive, mode="r:*") as opened_archive:
                members = _validate_tar(opened_archive, manifest, expected)
                safe_destination = _validate_destination(destination)
                stage = Path(
                    tempfile.mkdtemp(
                        prefix=f".{safe_destination.name}.stage-",
                        dir=safe_destination.parent,
                    )
                )
                _extract_members(opened_archive, members, stage)
                _replace_destination(stage, safe_destination)
                stage = None
    except ReleaseError:
        if stage is not None:
            _remove_stage(stage)
        raise
    except (OSError, tarfile.TarError) as exc:
        if stage is not None:
            _remove_stage(stage)
            raise ReleaseError(f"could not extract archive: {archive}") from exc
        raise ReleaseError(f"could not validate archive: {archive}") from exc


def _load_json(data: bytes) -> object:
    if type(data) is not bytes:
        raise ReleaseError("manifest input must be bytes")
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError as exc:
        raise ReleaseError(str(exc)) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("manifest must be valid UTF-8 JSON") from exc


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise json.JSONDecodeError(f"invalid JSON constant: {value}", value, 0)


def _require_object(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ReleaseError(f"{label} must be an object")
    return value


def _require_keys(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    actual = set(value)
    unknown = sorted(actual - expected)
    if unknown:
        raise ReleaseError(f"unknown {label} key: {unknown[0]}")
    missing = sorted(expected - actual)
    if missing:
        raise ReleaseError(f"missing {label} key: {missing[0]}")


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ReleaseError(f"{label} must be a non-empty string")
    return value


def _parse_artifact(
    value: object, index: int
) -> tuple[str, Mapping[str, ArtifactPin]]:
    artifact = _require_object(value, f"artifact {index}")
    _require_keys(
        artifact,
        {"name", "version", "tag", "repository", "spdx_license", "platforms"},
        "artifact",
    )

    name = _require_string(artifact["name"], "artifact name")
    if _NAME_RE.fullmatch(name) is None:
        raise ReleaseError(f"invalid artifact name: {name}")
    version = _require_string(artifact["version"], f"artifact {name} version")
    if _VERSION_RE.fullmatch(version) is None:
        raise ReleaseError(f"artifact {name} version must be semantic x.y.z")
    tag = _require_string(artifact["tag"], f"artifact {name} tag")
    if tag != f"v{version}":
        raise ReleaseError(f"artifact {name} tag must equal v{version}")
    repository = _require_string(
        artifact["repository"], f"artifact {name} repository"
    )
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise ReleaseError(f"artifact {name} repository is invalid")
    spdx_license = _require_string(
        artifact["spdx_license"], f"artifact {name} SPDX license"
    )
    if spdx_license not in _SUPPORTED_SPDX_LICENSES:
        raise ReleaseError(f"unsupported SPDX license: {spdx_license}")

    raw_platforms = _require_object(
        artifact["platforms"], f"artifact {name} platforms"
    )
    if set(raw_platforms) != _SUPPORTED_ARCHITECTURES:
        expected = ", ".join(sorted(_SUPPORTED_ARCHITECTURES))
        raise ReleaseError(f"artifact {name} platforms must be exactly: {expected}")

    platforms: dict[str, ArtifactPin] = {}
    for architecture in sorted(_SUPPORTED_ARCHITECTURES):
        platforms[architecture] = _parse_platform_pin(
            raw_platforms[architecture],
            name=name,
            version=version,
            tag=tag,
            repository=repository,
            spdx_license=spdx_license,
            architecture=architecture,
        )
    return name, MappingProxyType(platforms)


def _parse_platform_pin(
    value: object,
    *,
    name: str,
    version: str,
    tag: str,
    repository: str,
    spdx_license: str,
    architecture: str,
) -> ArtifactPin:
    pin = _require_object(value, f"artifact {name} platform {architecture}")
    required = {"architecture", "url", "sha256"}
    optional = {"executable_path", "executable_sha256"}
    actual = set(pin)
    unknown = sorted(actual - required - optional)
    if unknown:
        raise ReleaseError(f"unknown platform key: {unknown[0]}")
    missing = sorted(required - actual)
    if missing:
        raise ReleaseError(f"missing platform key: {missing[0]}")

    declared_architecture = _require_string(
        pin["architecture"], f"artifact {name} architecture"
    )
    if declared_architecture != architecture:
        raise ReleaseError(
            f"platform mismatch: key {architecture!r}, value "
            f"{declared_architecture!r}"
        )
    url = _require_string(pin["url"], f"artifact {name} URL")
    _validate_release_url(url, repository, tag, architecture)
    sha256 = _require_string(pin["sha256"], f"artifact {name} SHA-256")
    _require_sha256(sha256, f"artifact {name}")

    has_executable_path = "executable_path" in pin
    has_executable_sha256 = "executable_sha256" in pin
    if has_executable_path != has_executable_sha256:
        raise ReleaseError(
            "executable_path and executable_sha256 must be supplied together"
        )

    executable_path: str | None = None
    executable_sha256: str | None = None
    if has_executable_path:
        executable_path = _require_string(
            pin["executable_path"], f"artifact {name} executable path"
        )
        normalized = _normalize_archive_path(executable_path)
        if normalized != executable_path:
            raise ReleaseError(f"artifact {name} executable path must be canonical")
        executable_sha256 = _require_string(
            pin["executable_sha256"], f"artifact {name} executable SHA-256"
        )
        _require_sha256(executable_sha256, f"artifact {name} executable")

    return ArtifactPin(
        name=name,
        version=version,
        tag=tag,
        repository=repository,
        spdx_license=spdx_license,
        architecture=architecture,
        url=url,
        sha256=sha256,
        executable_path=executable_path,
        executable_sha256=executable_sha256,
    )


def _validate_release_url(
    url: str, repository: str, tag: str, architecture: str
) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ReleaseError("artifact URL must use HTTPS")
    if parsed.netloc != "github.com":
        raise ReleaseError("artifact URL must use the official GitHub host")
    if parsed.query or parsed.fragment:
        raise ReleaseError("artifact URL must not contain a query or fragment")
    if "latest" in parsed.path.lower():
        raise ReleaseError("artifact URL must be an immutable release URL")
    if "%" in parsed.path or "\\" in parsed.path:
        raise ReleaseError("artifact URL path must be canonical")

    owner, project = repository.split("/", 1)
    parts = parsed.path.split("/")
    if len(parts) != 7 or parts[:6] != [
        "",
        owner,
        project,
        "releases",
        "download",
        tag,
    ]:
        raise ReleaseError(
            "artifact URL repository and tag must match the reviewed artifact"
        )
    filename = parts[6]
    architecture_token = re.compile(
        rf"(?:^|[-_.]){re.escape(architecture)}(?:[-_.]|$)"
    )
    if not filename or architecture_token.search(filename) is None:
        raise ReleaseError(
            f"artifact URL filename must match architecture {architecture}"
        )


def _require_sha256(value: str, label: str) -> None:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReleaseError(f"{label} must be an exact lowercase SHA-256")


def _validate_archive_manifest(
    manifest: ArchiveManifest,
) -> dict[str, ArchiveEntry]:
    if type(manifest) is not ArchiveManifest:
        raise ReleaseError("archive manifest has an invalid type")
    if type(manifest.max_entries) is not int or manifest.max_entries <= 0:
        raise ReleaseError("archive max_entries must be a positive integer")
    if type(manifest.max_total_size) is not int or manifest.max_total_size < 0:
        raise ReleaseError("archive max_total_size must be a non-negative integer")
    if type(manifest.entries) is not tuple or not manifest.entries:
        raise ReleaseError("archive manifest entries must be a non-empty tuple")

    expected: dict[str, ArchiveEntry] = {}
    for entry in manifest.entries:
        if type(entry) is not ArchiveEntry:
            raise ReleaseError("archive manifest contains an invalid entry")
        normalized = _normalize_archive_path(entry.path)
        if normalized != entry.path:
            raise ReleaseError(f"archive manifest path must be canonical: {entry.path}")
        if normalized in expected:
            raise ReleaseError(f"duplicate archive manifest path: {normalized}")
        if entry.kind not in {"file", "directory", "symlink"}:
            raise ReleaseError(f"invalid archive manifest entry kind: {entry.kind}")
        if entry.mode is not None and (
            type(entry.mode) is not int or not 0 <= entry.mode <= 0o777
        ):
            raise ReleaseError(f"invalid archive manifest mode: {entry.path}")
        if entry.sha256 is not None:
            if entry.kind != "file":
                raise ReleaseError("only regular files may have a member SHA-256")
            _require_sha256(entry.sha256, f"archive member {entry.path}")
        if entry.kind == "symlink":
            if entry.link_target is None:
                raise ReleaseError(
                    f"symlink manifest entry requires a target: {entry.path}"
                )
            _resolve_symlink_target(entry.path, entry.link_target)
        elif entry.link_target is not None:
            raise ReleaseError(
                f"non-symlink manifest entry has a target: {entry.path}"
            )
        expected[normalized] = entry
    return expected


def _validate_tar(
    archive: tarfile.TarFile,
    manifest: ArchiveManifest,
    expected: Mapping[str, ArchiveEntry],
) -> tuple[_ValidatedMember, ...]:
    actual: dict[str, _ValidatedMember] = {}
    total_size = 0

    for count, info in enumerate(archive, start=1):
        if count > manifest.max_entries:
            raise ReleaseError(
                f"archive entry count limit exceeded: {manifest.max_entries}"
            )
        path = _normalize_archive_path(info.name)
        if path in actual:
            raise ReleaseError(f"duplicate normalized archive path: {path}")
        kind = _tar_member_kind(info)
        if info.mode & 0o6000:
            raise ReleaseError(f"archive entry has setuid or setgid mode: {path}")
        if info.size < 0:
            raise ReleaseError(f"archive entry has a negative size: {path}")
        if kind == "file":
            total_size += info.size
            if total_size > manifest.max_total_size:
                raise ReleaseError(
                    f"archive size limit exceeded: {manifest.max_total_size}"
                )

        expected_entry = expected.get(path)
        if expected_entry is None:
            raise ReleaseError(f"unexpected archive entry: {path}")
        if kind != expected_entry.kind:
            raise ReleaseError(
                f"archive entry type mismatch for {path}: expected "
                f"{expected_entry.kind}, got {kind}"
            )
        actual_mode = info.mode & 0o777
        if expected_entry.mode is not None and actual_mode != expected_entry.mode:
            raise ReleaseError(
                f"archive entry mode mismatch for {path}: expected "
                f"{expected_entry.mode:o}, got {actual_mode:o}"
            )

        resolved_link_target: str | None = None
        if kind == "symlink":
            resolved_link_target = _resolve_symlink_target(path, info.linkname)
            if info.linkname != expected_entry.link_target:
                raise ReleaseError(f"archive symlink target mismatch for {path}")
        elif expected_entry.sha256 is not None:
            _verify_tar_member_digest(archive, info, expected_entry.sha256)

        actual[path] = _ValidatedMember(
            path=path,
            kind=kind,
            info=info,
            expected=expected_entry,
            resolved_link_target=resolved_link_target,
        )

    missing = sorted(set(expected) - set(actual))
    if missing:
        raise ReleaseError(f"missing archive entry: {missing[0]}")

    for member in actual.values():
        parent = PurePosixPath(member.path).parent
        while str(parent) != ".":
            parent_member = actual.get(str(parent))
            if parent_member is not None and parent_member.kind != "directory":
                raise ReleaseError(
                    f"archive path has a non-directory parent: {member.path}"
                )
            parent = parent.parent

    for member in actual.values():
        if member.kind == "symlink":
            assert member.resolved_link_target is not None
            if member.resolved_link_target not in actual:
                raise ReleaseError(
                    f"archive symlink target is not an internal entry: {member.path}"
                )

    return tuple(actual.values())


def _normalize_archive_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        raise ReleaseError(f"unsafe archive path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ReleaseError(f"unsafe archive path: {value}")
    normalized = str(path)
    if normalized in {"", "."}:
        raise ReleaseError(f"unsafe archive path: {value}")
    return normalized


def _resolve_symlink_target(member_path: str, target: str) -> str:
    if (
        type(target) is not str
        or not target
        or "\x00" in target
        or "\\" in target
        or PurePosixPath(target).is_absolute()
    ):
        raise ReleaseError(f"unsafe symlink target for {member_path}: {target!r}")

    parts = list(PurePosixPath(member_path).parent.parts)
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise ReleaseError(
                    f"unsafe symlink target for {member_path}: {target}"
                )
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise ReleaseError(f"unsafe symlink target for {member_path}: {target}")
    return "/".join(parts)


def _tar_member_kind(info: tarfile.TarInfo) -> str:
    if info.isreg() and not info.issparse():
        return "file"
    if info.isdir():
        return "directory"
    if info.issym():
        return "symlink"
    raise ReleaseError(f"unsupported archive entry type: {info.name}")


def _verify_tar_member_digest(
    archive: tarfile.TarFile, info: tarfile.TarInfo, expected_sha256: str
) -> None:
    source = archive.extractfile(info)
    if source is None:
        raise ReleaseError(f"could not read archive member: {info.name}")
    digest = hashlib.sha256()
    with source:
        while chunk := source.read(_COPY_CHUNK_SIZE):
            digest.update(chunk)
    if not secrets.compare_digest(digest.hexdigest(), expected_sha256):
        raise ReleaseError(f"archive member digest mismatch: {info.name}")


def _validate_destination(destination: Path) -> Path:
    if type(destination) is not Path:
        destination = Path(destination)
    absolute = destination.absolute()
    if absolute.name in {"", ".", ".."}:
        raise ReleaseError("destination path is invalid")

    current = Path(absolute.anchor)
    for component in absolute.parent.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise ReleaseError(f"destination parent does not exist: {current}") from exc
        except OSError as exc:
            raise ReleaseError(f"could not inspect destination parent: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ReleaseError(f"destination parent is a symlink: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ReleaseError(f"destination parent is not a directory: {current}")

    try:
        destination_metadata = absolute.lstat()
    except FileNotFoundError:
        return absolute
    except OSError as exc:
        raise ReleaseError(f"could not inspect destination: {absolute}") from exc
    if stat.S_ISLNK(destination_metadata.st_mode):
        raise ReleaseError("destination must not be a symlink")
    if not stat.S_ISDIR(destination_metadata.st_mode):
        raise ReleaseError("destination must be a directory or absent")
    return absolute


def _extract_members(
    archive: tarfile.TarFile,
    members: tuple[_ValidatedMember, ...],
    stage: Path,
) -> None:
    directories = sorted(
        (member for member in members if member.kind == "directory"),
        key=lambda member: (len(PurePosixPath(member.path).parts), member.path),
    )
    files = sorted(
        (member for member in members if member.kind == "file"),
        key=lambda member: member.path,
    )
    symlinks = sorted(
        (member for member in members if member.kind == "symlink"),
        key=lambda member: member.path,
    )

    for member in directories:
        target = stage.joinpath(*PurePosixPath(member.path).parts)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not target.is_dir() or target.is_symlink():
            raise ReleaseError(f"could not create archive directory: {member.path}")

    for member in files:
        target = stage.joinpath(*PurePosixPath(member.path).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _copy_regular_member(archive, member.info, target)
        os.chmod(target, member.info.mode & 0o777, follow_symlinks=False)

    for member in symlinks:
        target = stage.joinpath(*PurePosixPath(member.path).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.symlink(member.info.linkname, target)

    for member in reversed(directories):
        target = stage.joinpath(*PurePosixPath(member.path).parts)
        os.chmod(target, member.info.mode & 0o777, follow_symlinks=False)


def _copy_regular_member(
    archive: tarfile.TarFile, info: tarfile.TarInfo, destination: Path
) -> None:
    source = archive.extractfile(info)
    if source is None:
        raise ReleaseError(f"could not read archive member: {info.name}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    copied = 0
    try:
        with source, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while chunk := source.read(_COPY_CHUNK_SIZE):
                output.write(chunk)
                copied += len(chunk)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if copied != info.size:
        raise ReleaseError(
            f"archive member size changed while extracting: {info.name}"
        )


def _replace_destination(stage: Path, destination: Path) -> None:
    if not destination.exists():
        os.replace(stage, destination)
        return

    backup = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.backup-", dir=destination.parent
        )
    )
    backup.rmdir()
    os.replace(destination, backup)
    try:
        os.replace(stage, destination)
    except OSError:
        os.replace(backup, destination)
        raise
    shutil.rmtree(backup)


def _remove_stage(stage: Path) -> None:
    try:
        shutil.rmtree(stage)
    except FileNotFoundError:
        pass
