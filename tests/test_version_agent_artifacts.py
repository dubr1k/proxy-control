from __future__ import annotations

import io
import tarfile
import zipfile

import pytest

from version_agent.artifacts import ArtifactError, extract_member


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _targz(entries: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
    return buffer.getvalue()


def test_zip_member_is_returned_by_exact_name():
    assert extract_member(_zip({"xray": b"bin", "geoip.dat": b"geo"}), {"format": "zip"}, "xray") == b"bin"


def test_tar_member_may_sit_under_a_directory():
    payload = _targz({"mita_3.37.0_linux_amd64/mita": b"bin"})
    assert extract_member(payload, {"format": "tar.gz"}, "mita_3.37.0_linux_amd64/mita") == b"bin"


def test_tar_member_written_with_a_dot_slash_prefix_is_still_found():
    payload = _targz({"./mita": b"bin"})
    assert extract_member(payload, {"format": "tar.gz"}, "mita") == b"bin"


def test_missing_member_symlink_and_oversize_are_refused():
    with pytest.raises(ArtifactError, match="member not found"):
        extract_member(_zip({"xray": b"bin"}), {"format": "zip"}, "geoip.dat")
    with pytest.raises(ArtifactError, match="not a regular file"):
        extract_member(_targz({}, symlink="mita"), {"format": "tar.gz"}, "mita")
    with pytest.raises(ArtifactError, match="too large"):
        extract_member(_zip({"xray": b"x" * 32}), {"format": "zip"}, "xray", maximum=16)


def test_escaping_members_unknown_formats_and_garbage_are_refused():
    with pytest.raises(ArtifactError, match="invalid archive member"):
        extract_member(_zip({"xray": b"bin"}), {"format": "zip"}, "../xray")
    with pytest.raises(ArtifactError, match="invalid archive member"):
        extract_member(_zip({"xray": b"bin"}), {"format": "zip"}, "/xray")
    with pytest.raises(ArtifactError, match="unsupported archive format"):
        extract_member(_zip({"xray": b"bin"}), {"format": "rar"}, "xray")
    with pytest.raises(ArtifactError, match="unreadable"):
        extract_member(b"not an archive", {"format": "zip"}, "xray")
    with pytest.raises(ArtifactError, match="unreadable"):
        extract_member(b"not an archive", {"format": "tar.gz"}, "mita")
