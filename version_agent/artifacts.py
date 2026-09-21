"""Pull one regular file out of a release archive the agent already verified by SHA-256."""
from __future__ import annotations

import io
import stat
import tarfile
import zipfile


class ArtifactError(ValueError):
    """The archive does not hold the member the catalog names, or holds it unsafely."""


def _normalized(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def extract_member(
    payload: bytes, archive: dict, member: str, *, maximum: int = 256 * 1024 * 1024
) -> bytes:
    if not member or member.startswith("/") or ".." in member.split("/"):
        raise ArtifactError("invalid archive member")
    fmt = archive.get("format")
    if fmt not in ("zip", "tar.gz"):
        raise ArtifactError("unsupported archive format")
    try:
        if fmt == "zip":
            return _from_zip(payload, member, maximum)
        return _from_tar(payload, member, maximum)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError) as exc:
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError("archive is unreadable") from exc


def _from_zip(payload: bytes, member: str, maximum: int) -> bytes:
    with zipfile.ZipFile(io.BytesIO(payload)) as bundle:
        found = None
        for info in bundle.infolist():
            if _normalized(info.filename) == member:
                found = info
                break
        if found is None:
            raise ArtifactError("archive member not found")
        mode = (found.external_attr >> 16) & 0o170000
        if found.is_dir() or (mode and mode != stat.S_IFREG):
            raise ArtifactError("archive member is not a regular file")
        if found.file_size > maximum:
            raise ArtifactError("archive member is too large")
        with bundle.open(found) as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise ArtifactError("archive member is too large")
        return data


def _from_tar(payload: bytes, member: str, maximum: int) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as bundle:
        for info in bundle:
            if _normalized(info.name) != member:
                continue
            if not info.isreg():
                raise ArtifactError("archive member is not a regular file")
            if info.size > maximum:
                raise ArtifactError("archive member is too large")
            handle = bundle.extractfile(info)
            if handle is None:
                raise ArtifactError("archive member is not a regular file")
            with handle:
                data = handle.read(maximum + 1)
            if len(data) > maximum:
                raise ArtifactError("archive member is too large")
            return data
    raise ArtifactError("archive member not found")
