from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import secrets
import stat
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import BinaryIO, Mapping
from urllib.parse import urlsplit

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SUPPORTED_ARCHITECTURES = frozenset({"amd64", "arm64"})
_SUPPORTED_SPDX_LICENSES = frozenset({"GPL-3.0-only", "GPL-3.0-or-later"})
_COPY_CHUNK_SIZE = 1024 * 1024
_HARD_MAX_DECOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024
_HARD_MAX_METADATA_SIZE = 8 * 1024 * 1024
_DEFAULT_MAX_DECOMPRESSED_SIZE = 1024 * 1024 * 1024
_DEFAULT_MAX_METADATA_SIZE = 1024 * 1024
_TAR_BLOCK_SIZE = 512
_TAR_EXTENSION_TYPES = frozenset(
    {
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    }
)


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
    archive_sha256: str
    max_entries: int = 10_000
    max_total_size: int = 1024 * 1024 * 1024
    max_decompressed_size: int = _DEFAULT_MAX_DECOMPRESSED_SIZE
    max_metadata_size: int = _DEFAULT_MAX_METADATA_SIZE


@dataclass(frozen=True)
class _ValidatedMember:
    path: str
    kind: str
    info: tarfile.TarInfo
    expected: ArchiveEntry
    resolved_link_target: str | None = None


@dataclass
class _DestinationAnchor:
    absolute: Path
    components: tuple[str, ...]
    descriptors: tuple[int, ...]
    identities: tuple[tuple[int, int], ...]
    destination_identity: tuple[int, int] | None

    @property
    def parent_fd(self) -> int:
        return self.descriptors[-1]

    @property
    def destination_name(self) -> str:
        return self.absolute.name

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def verify_artifact(path: Path, expected_sha256: str) -> None:
    """Stream one no-follow file descriptor and compare its reviewed SHA-256."""

    _require_sha256(expected_sha256, "expected artifact")
    descriptor = _open_regular_file(path, "artifact")
    try:
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            actual = _digest_open_file(source)
    except OSError as exc:
        raise ReleaseError(f"could not read artifact: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

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
    """Verify and validate one opened archive before a dirfd-anchored install."""

    expected = _validate_archive_manifest(manifest)
    anchor: _DestinationAnchor | None = None
    stage_name: str | None = None
    stage_fd = -1
    descriptor = _open_regular_file(archive, "archive")
    try:
        with os.fdopen(descriptor, "rb") as raw_archive:
            descriptor = -1
            _verify_open_archive(raw_archive, manifest.archive_sha256, archive)
            with tempfile.TemporaryFile(mode="w+b") as decoded_archive:
                _decode_bounded_tar(
                    raw_archive,
                    decoded_archive,
                    manifest.max_decompressed_size,
                )
                _scan_tar_records(decoded_archive, manifest.max_metadata_size)
                decoded_archive.seek(0)
                with tarfile.open(
                    fileobj=decoded_archive, mode="r:"
                ) as opened_archive:
                    members = _validate_tar(opened_archive, manifest, expected)
                    anchor = _validate_destination(destination)
                    _revalidate_destination(anchor)
                    stage_name, stage_fd = _create_private_stage(anchor)
                    _extract_members(opened_archive, members, stage_fd)
                    os.close(stage_fd)
                    stage_fd = -1
                    _revalidate_destination(anchor)
                    _replace_destination(anchor, stage_name)
                    stage_name = None
    except ReleaseError:
        if stage_fd >= 0:
            os.close(stage_fd)
            stage_fd = -1
        if anchor is not None and stage_name is not None:
            _best_effort_remove_tree_at(anchor.parent_fd, stage_name)
        raise
    except (OSError, tarfile.TarError, gzip.BadGzipFile) as exc:
        if stage_fd >= 0:
            os.close(stage_fd)
            stage_fd = -1
        if anchor is not None and stage_name is not None:
            _best_effort_remove_tree_at(anchor.parent_fd, stage_name)
            raise ReleaseError(f"could not extract archive: {archive}") from exc
        raise ReleaseError(f"could not validate archive: {archive}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if anchor is not None:
            anchor.close()


def _open_regular_file(path: Path, label: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseError(f"{label} is not a regular file: {path}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ReleaseError(f"{label} is not a regular file: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _digest_open_file(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(_COPY_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def _verify_open_archive(
    source: BinaryIO, expected_sha256: str, archive_path: Path
) -> None:
    actual = _digest_open_file(source)
    if not secrets.compare_digest(actual, expected_sha256):
        raise ReleaseError(
            f"archive digest mismatch for {archive_path.name}: expected "
            f"{expected_sha256}, got {actual}"
        )
    source.seek(0)


def _decode_bounded_tar(
    raw_archive: BinaryIO,
    decoded_archive: BinaryIO,
    max_decompressed_size: int,
) -> None:
    raw_archive.seek(0)
    magic = raw_archive.read(6)
    raw_archive.seek(0)
    if magic.startswith(b"\x1f\x8b"):
        source: BinaryIO = gzip.GzipFile(fileobj=raw_archive, mode="rb")
        close_source = True
    elif magic.startswith((b"BZh", b"\xfd7zXZ\x00")):
        raise ReleaseError("unsupported archive compression; use gzip or tar")
    else:
        source = raw_archive
        close_source = False

    total = 0
    try:
        while True:
            chunk = source.read(min(_COPY_CHUNK_SIZE, max_decompressed_size - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > max_decompressed_size:
                raise ReleaseError(
                    "decompressed archive size limit exceeded: "
                    f"{max_decompressed_size}"
                )
            decoded_archive.write(chunk)
    finally:
        if close_source:
            source.close()
    decoded_archive.flush()
    decoded_archive.seek(0)


def _scan_tar_records(source: BinaryIO, max_metadata_size: int) -> None:
    source.seek(0, os.SEEK_END)
    decompressed_size = source.tell()
    source.seek(0)
    offset = 0
    metadata_size = 0

    while offset + _TAR_BLOCK_SIZE <= decompressed_size:
        header = source.read(_TAR_BLOCK_SIZE)
        if len(header) != _TAR_BLOCK_SIZE:
            raise ReleaseError("truncated tar header")
        if not any(header):
            source.seek(0)
            return

        payload_size = _parse_tar_size(header[124:136])
        entry_type = header[156:157]
        if entry_type in _TAR_EXTENSION_TYPES:
            metadata_size += payload_size
            if metadata_size > max_metadata_size:
                raise ReleaseError(
                    f"tar metadata limit exceeded: {max_metadata_size}"
                )
        elif entry_type not in {tarfile.REGTYPE, tarfile.AREGTYPE} and payload_size:
            raise ReleaseError("payload-bearing non-regular tar entry")

        padded_size = (
            (payload_size + _TAR_BLOCK_SIZE - 1) // _TAR_BLOCK_SIZE
        ) * _TAR_BLOCK_SIZE
        offset += _TAR_BLOCK_SIZE + padded_size
        if offset > decompressed_size:
            raise ReleaseError("tar entry exceeds decompressed archive")
        source.seek(offset)

    raise ReleaseError("tar archive is missing a zero terminator")


def _parse_tar_size(field: bytes) -> int:
    if field[0] & 0x80:
        raise ReleaseError("unsupported tar numeric encoding")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    if any(character not in b"01234567" for character in value):
        raise ReleaseError("invalid tar size field")
    return int(value, 8)


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
    if not url.isascii():
        raise ReleaseError("artifact URL must use canonical ASCII")
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
           for character in url):
        raise ReleaseError("artifact URL must not contain whitespace or control characters")

    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise ReleaseError("artifact URL must use HTTPS")
    if parsed.netloc != "github.com":
        raise ReleaseError("artifact URL must use the official GitHub host")
    if parsed.query or parsed.fragment:
        raise ReleaseError("artifact URL must not contain a query or fragment")
    canonical = f"https://github.com{parsed.path}"
    if url != canonical:
        raise ReleaseError("artifact URL must use exact canonical form")
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
    _require_sha256(manifest.archive_sha256, "archive")
    if (
        type(manifest.max_decompressed_size) is not int
        or not 0 < manifest.max_decompressed_size <= _HARD_MAX_DECOMPRESSED_SIZE
    ):
        raise ReleaseError(
            "archive max_decompressed_size must be within the hard safety bound"
        )
    if (
        type(manifest.max_metadata_size) is not int
        or not 0 <= manifest.max_metadata_size <= _HARD_MAX_METADATA_SIZE
    ):
        raise ReleaseError(
            "archive max_metadata_size must be within the hard safety bound"
        )
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
        if kind != "file" and info.size:
            raise ReleaseError(f"payload-bearing non-regular tar entry: {path}")
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


def _validate_destination(destination: Path) -> _DestinationAnchor:
    absolute = Path(destination).absolute()
    if absolute.name in {"", ".", ".."}:
        raise ReleaseError("destination path is invalid")

    components = tuple(absolute.parent.parts[1:])
    descriptors: list[int] = []
    identities: list[tuple[int, int]] = []
    try:
        root_fd = os.open(absolute.anchor, _directory_open_flags())
        descriptors.append(root_fd)
        identities.append(_identity(os.fstat(root_fd)))

        for component in components:
            before = os.stat(component, dir_fd=descriptors[-1], follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ReleaseError(
                    f"destination parent is a symlink: {component}"
                )
            if not stat.S_ISDIR(before.st_mode):
                raise ReleaseError(
                    f"destination parent is not a directory: {component}"
                )
            child_fd = os.open(
                component,
                _directory_open_flags(),
                dir_fd=descriptors[-1],
            )
            after = os.fstat(child_fd)
            if _identity(before) != _identity(after):
                os.close(child_fd)
                raise ReleaseError("destination parent changed during validation")
            descriptors.append(child_fd)
            identities.append(_identity(after))

        destination_identity = _destination_identity(
            descriptors[-1], absolute.name
        )
        return _DestinationAnchor(
            absolute=absolute,
            components=components,
            descriptors=tuple(descriptors),
            identities=tuple(identities),
            destination_identity=destination_identity,
        )
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _destination_identity(parent_fd: int, name: str) -> tuple[int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        raise ReleaseError("destination must not be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseError("destination must be a directory or absent")
    return _identity(metadata)


def _revalidate_destination(anchor: _DestinationAnchor) -> None:
    try:
        for index, component in enumerate(anchor.components):
            metadata = os.stat(
                component,
                dir_fd=anchor.descriptors[index],
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or _identity(metadata) != anchor.identities[index + 1]
            ):
                raise ReleaseError("destination parent changed before mutation")
        current_destination = _destination_identity(
            anchor.parent_fd, anchor.destination_name
        )
    except FileNotFoundError as exc:
        raise ReleaseError("destination parent changed before mutation") from exc
    except OSError as exc:
        raise ReleaseError("could not revalidate destination parent") from exc

    if current_destination != anchor.destination_identity:
        raise ReleaseError("destination changed before mutation")


def _create_private_stage(anchor: _DestinationAnchor) -> tuple[str, int]:
    name = _reserve_directory_name(
        anchor.parent_fd, f".{anchor.destination_name}.stage-"
    )
    try:
        descriptor = os.open(
            name,
            _directory_open_flags(),
            dir_fd=anchor.parent_fd,
        )
    except BaseException:
        _best_effort_remove_tree_at(anchor.parent_fd, name)
        raise
    return name, descriptor


def _reserve_directory_name(parent_fd: int, prefix: str) -> str:
    for _attempt in range(32):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        return name
    raise ReleaseError("could not reserve a private destination entry")


def _extract_members(
    archive: tarfile.TarFile,
    members: tuple[_ValidatedMember, ...],
    stage_fd: int,
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
        descriptor = _open_or_create_directory(
            stage_fd, PurePosixPath(member.path).parts
        )
        os.close(descriptor)

    for member in files:
        parts = PurePosixPath(member.path).parts
        parent_fd = _open_or_create_directory(stage_fd, parts[:-1])
        try:
            _copy_regular_member(
                archive,
                member.info,
                parent_fd,
                parts[-1],
                member.expected.sha256,
            )
        finally:
            os.close(parent_fd)

    for member in symlinks:
        parts = PurePosixPath(member.path).parts
        parent_fd = _open_or_create_directory(stage_fd, parts[:-1])
        try:
            os.symlink(member.info.linkname, parts[-1], dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    for member in reversed(directories):
        descriptor = _open_or_create_directory(
            stage_fd, PurePosixPath(member.path).parts
        )
        try:
            os.fchmod(descriptor, member.info.mode & 0o777)
        finally:
            os.close(descriptor)
    os.fsync(stage_fd)


def _open_or_create_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    current_fd = os.dup(root_fd)
    try:
        for component in parts:
            try:
                os.mkdir(component, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            metadata = os.stat(
                component, dir_fd=current_fd, follow_symlinks=False
            )
            if not stat.S_ISDIR(metadata.st_mode):
                raise ReleaseError(
                    f"archive parent is not a directory: {component}"
                )
            child_fd = os.open(
                component,
                _directory_open_flags(),
                dir_fd=current_fd,
            )
            if _identity(metadata) != _identity(os.fstat(child_fd)):
                os.close(child_fd)
                raise ReleaseError("archive directory changed while extracting")
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _copy_regular_member(
    archive: tarfile.TarFile,
    info: tarfile.TarInfo,
    parent_fd: int,
    name: str,
    expected_sha256: str | None,
) -> None:
    source = archive.extractfile(info)
    if source is None:
        raise ReleaseError(f"could not read archive member: {info.name}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
    copied = 0
    digest = hashlib.sha256() if expected_sha256 is not None else None
    try:
        with source, os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            while chunk := source.read(_COPY_CHUNK_SIZE):
                output.write(chunk)
                copied += len(chunk)
                if digest is not None:
                    digest.update(chunk)
            if copied != info.size:
                raise ReleaseError(
                    f"archive member size changed while extracting: {info.name}"
                )
            if (
                digest is not None
                and expected_sha256 is not None
                and not secrets.compare_digest(
                    digest.hexdigest(), expected_sha256
                )
            ):
                raise ReleaseError(
                    f"archive member changed while extracting: {info.name}"
                )
            os.fchmod(output.fileno(), info.mode & 0o777)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _replace_destination(
    anchor: _DestinationAnchor,
    stage_name: str,
) -> None:
    _revalidate_destination(anchor)
    parent_fd = anchor.parent_fd
    destination_name = anchor.destination_name
    if anchor.destination_identity is None:
        os.rename(
            stage_name,
            destination_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        return

    backup_name = _reserve_directory_name(
        parent_fd, f".{destination_name}.backup-"
    )
    try:
        os.rename(
            destination_name,
            backup_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    except BaseException:
        _best_effort_remove_tree_at(parent_fd, backup_name)
        raise

    try:
        os.rename(
            stage_name,
            destination_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    except OSError as replacement_error:
        try:
            os.rename(
                backup_name,
                destination_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except OSError as restore_error:
            raise ReleaseError(
                "destination replacement and rollback both failed"
            ) from restore_error
        raise replacement_error

    try:
        _remove_tree_at(parent_fd, backup_name)
    except OSError:
        # The new destination is already committed. Leave the old tree under
        # its unpredictable private quarantine name rather than report a
        # false extraction failure or touch it through a pathname.
        pass


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return

    descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    try:
        if _identity(metadata) != _identity(os.fstat(descriptor)):
            raise OSError("directory changed during cleanup")
        for child in os.listdir(descriptor):
            _remove_tree_at(descriptor, child)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)


def _best_effort_remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        _remove_tree_at(parent_fd, name)
    except OSError:
        pass
