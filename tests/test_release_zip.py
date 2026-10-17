"""The Xray artifact (v0.5): a reviewed zip whose three named members are extracted by a
bounded extractor — nothing else in the archive is ever written to disk."""
from __future__ import annotations

import hashlib
import io
import os
import stat
import zipfile
from pathlib import Path

import pytest

from installer.release import MemberPin, ReleaseError, ReleaseManifest, safe_extract_zip

ROOT = Path(__file__).resolve().parents[1]
RELEASE_MANIFEST = ROOT / "release" / "external-artifacts.json"
XRAY_SHA256 = "ecdd54eccd24c4c21a8f00968e7dbf7f5996da92383d2321170b560dc4a95158"
MEMBERS = {
    "xray": ("6771b2b2700dee175357024738ad579de1c3f2c49eec0257e737d5aa38d12fed", 34971772, 0o755),
    "geoip.dat": ("010bfc2e353c5e34e23156004944444ca260bae999e73171bdd7974056557959", 16587403, 0o644),
    "geosite.dat": ("8474140bc89940897ee2b629be8fc92f34a496bd32e45829605d17715f4340d6", 11205406, 0o644),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip(tmp_path: Path, members: dict[str, bytes], *, extras: bool = True) -> Path:
    archive = tmp_path / "Xray-linux-64.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
        if extras:
            bundle.writestr("README.md", b"# not extracted")
            bundle.writestr("evil/../escape", b"nope")
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(info, "/etc/passwd")
    return archive


def _pins(members: dict[str, bytes], *, modes: dict[str, int] | None = None) -> dict[str, MemberPin]:
    modes = modes or {}
    return {name: MemberPin(sha256=_sha(data), size=len(data), mode=modes.get(name, 0o644))
            for name, data in members.items()}


def test_safe_extract_zip_extracts_named_members_only(tmp_path):
    members = {"xray": b"\x7fELF" + os.urandom(64), "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    archive = _zip(tmp_path, members)
    destination = tmp_path / "out"
    safe_extract_zip(archive, destination, _pins(members, modes={"xray": 0o755}))
    assert sorted(path.name for path in destination.iterdir()) == ["geoip.dat", "geosite.dat", "xray"]
    assert (destination / "xray").read_bytes() == members["xray"]
    assert stat.S_IMODE((destination / "xray").stat().st_mode) == 0o755
    assert stat.S_IMODE((destination / "geoip.dat").stat().st_mode) == 0o644
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755


def test_safe_extract_zip_rejects_member_digest_mismatch(tmp_path):
    members = {"xray": b"binary", "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    archive = _zip(tmp_path, members)
    pins = _pins(members)
    pins["geosite.dat"] = MemberPin(sha256="0" * 64, size=7, mode=0o644)
    destination = tmp_path / "out"
    with pytest.raises(ReleaseError, match="geosite.dat"):
        safe_extract_zip(archive, destination, pins)
    assert not destination.exists()


def test_safe_extract_zip_rejects_oversized_and_undersized_members(tmp_path):
    members = {"xray": b"binary", "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    archive = _zip(tmp_path, members)
    pins = _pins(members)
    pins["xray"] = MemberPin(sha256=_sha(b"binary"), size=3, mode=0o755)
    with pytest.raises(ReleaseError, match="size"):
        safe_extract_zip(archive, tmp_path / "out", pins)
    with pytest.raises(ReleaseError, match="size"):
        safe_extract_zip(archive, tmp_path / "out", _pins(members), max_member_bytes=4)
    assert not (tmp_path / "out").exists()


def test_safe_extract_zip_rejects_missing_member_and_bad_names(tmp_path):
    members = {"xray": b"binary", "geoip.dat": b"geoip"}
    archive = _zip(tmp_path, members)
    pins = _pins({**members, "geosite.dat": b"geosite"})
    with pytest.raises(ReleaseError, match="geosite.dat"):
        safe_extract_zip(archive, tmp_path / "out", pins)
    with pytest.raises(ReleaseError, match="member name"):
        safe_extract_zip(archive, tmp_path / "out", {"../xray": MemberPin(sha256="0" * 64, size=1, mode=0o644)})
    with pytest.raises(ReleaseError, match="member name"):
        safe_extract_zip(archive, tmp_path / "out", {"bin/xray": MemberPin(sha256="0" * 64, size=1, mode=0o644)})


def test_safe_extract_zip_replaces_a_previous_install_atomically(tmp_path):
    members = {"xray": b"one", "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    destination = tmp_path / "out"
    safe_extract_zip(_zip(tmp_path, members), destination, _pins(members))
    (destination / "stale").write_bytes(b"left over")
    newer = {**members, "xray": b"two"}
    safe_extract_zip(_zip(tmp_path, newer), destination, _pins(newer))
    assert (destination / "xray").read_bytes() == b"two"
    assert not (destination / "stale").exists()
    assert not list(destination.parent.glob(".out.stage-*"))


def test_safe_extract_zip_refuses_symlinked_destination(tmp_path):
    members = {"xray": b"one", "geoip.dat": b"geoip", "geosite.dat": b"geosite"}
    target = tmp_path / "elsewhere"
    target.mkdir()
    destination = tmp_path / "out"
    destination.symlink_to(target)
    with pytest.raises(ReleaseError):
        safe_extract_zip(_zip(tmp_path, members), destination, _pins(members))
    assert not list(target.iterdir())


def test_xray_pin_includes_archive_and_member_digests():
    manifest = ReleaseManifest.from_bytes(RELEASE_MANIFEST.read_bytes())
    pin = manifest.external_artifact("xray", "amd64")
    assert pin.version == "26.10.17" and pin.tag == "v26.10.17"
    assert pin.url == "https://github.com/XTLS/Xray-core/releases/download/v26.10.17/Xray-linux-64.zip"
    assert pin.sha256 == XRAY_SHA256
    assert pin.spdx_license == "MPL-2.0"
    assert pin.executable_path is None
    assert set(pin.members) == set(MEMBERS)
    for name, (digest, size, mode) in MEMBERS.items():
        assert pin.members[name] == MemberPin(sha256=digest, size=size, mode=mode)


def test_manifest_members_are_validated():
    base = RELEASE_MANIFEST.read_text()
    with pytest.raises(ReleaseError, match="member"):
        ReleaseManifest.from_bytes(base.replace('"mode": "0755"', '"mode": "4755"').encode())
    with pytest.raises(ReleaseError, match="member"):
        ReleaseManifest.from_bytes(base.replace('"xray": {', '"bin/xray": {').encode())
    with pytest.raises(ReleaseError, match="architecture"):
        ReleaseManifest.from_bytes(base.replace('"filename_architecture": "64"', '"filename_architecture": "arm"').encode())


def test_zip_stream_is_read_in_bounded_chunks(tmp_path):
    # A member declared small in the central directory but larger in the stream must not be
    # trusted: the extractor counts bytes as it goes.
    members = {"xray": b"x" * 3000, "geoip.dat": b"g", "geosite.dat": b"s"}
    archive = _zip(tmp_path, members, extras=False)
    raw = bytearray(archive.read_bytes())
    # Lie about the size of the first member in the central directory (file_size field).
    with zipfile.ZipFile(io.BytesIO(bytes(raw))) as bundle:
        info = bundle.getinfo("xray")
    offset = raw.rfind(b"xray") - 46 + 24  # central directory header: uncompressed size at +24
    assert info.file_size == 3000
    raw[offset:offset + 4] = (10).to_bytes(4, "little")
    archive.write_bytes(bytes(raw))
    pins = _pins(members)
    pins["xray"] = MemberPin(sha256=_sha(b"x" * 3000), size=10, mode=0o644)
    with pytest.raises(ReleaseError):
        safe_extract_zip(archive, tmp_path / "out", pins)
    assert not (tmp_path / "out").exists()
