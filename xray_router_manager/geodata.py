"""Geodata of the router (v0.8): where `geosite.dat` / `geoip.dat` come from and how they change.

The files Xray resolves `geosite:` / `geoip:` codes against live in the manager's own state
directory (`<state>/geodata`), never in the read-only binary directory: the installer's pinned
pair is the **seed** the manager copies there on first start, and everything after that is the
operator's choice — the seed again, the Loyalsoldier community lists, or any two HTTPS URLs.

An update is a transaction: both files are downloaded to a temporary name (size-capped, HTTPS
only, the `<url>.sha256sum` sidecar honoured when the publisher offers one), the running
generation's config is `xray run -test`-ed against the candidates (a code the new lists no
longer know fails here, not at runtime), then the files are swapped atomically and the router
restarts on them. A failure leaves the previous files in place and is recorded as `last_error`.
Automatic updates run from the manager's watchdog thread at the configured interval.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

FILES = ("geosite", "geoip")
SOURCE_KINDS = ("xray", "loyalsoldier", "custom")
LOYALSOLDIER_URLS = {
    "geosite": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    "geoip": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
}
MAX_FILE_BYTES = 64 * 1024 * 1024
MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS = 1, 24 * 14, 24
DOWNLOAD_TIMEOUT = 60.0
USER_AGENT = "proxy-control-xray-router/0.8"
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{1,5})?/[^\s]{1,1024}$")
_SHA256 = re.compile(r"\b([0-9a-fA-F]{64})\b")
_RELEASE_TAG = re.compile(r"/releases/download/([^/]+)/")


class GeodataError(Exception):
    """A geodata operation the manager refuses or could not finish; `code` is what the panel shows."""

    def __init__(self, message: str, code: str = "geodata_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Source:
    kind: str
    geosite_url: str | None = None
    geoip_url: str | None = None

    def urls(self) -> dict[str, str] | None:
        if self.kind == "loyalsoldier":
            return dict(LOYALSOLDIER_URLS)
        if self.kind == "custom":
            return {"geosite": self.geosite_url or "", "geoip": self.geoip_url or ""}
        return None

    def wire(self) -> dict:
        return {"kind": self.kind, "geosite_url": self.geosite_url, "geoip_url": self.geoip_url}


def parse_source(value: object) -> Source:
    """`{"kind": ..., "geosite_url"?, "geoip_url"?}` validated: custom needs two HTTPS URLs."""
    if not isinstance(value, dict) or value.get("kind") not in SOURCE_KINDS:
        raise GeodataError("source.kind must be xray, loyalsoldier or custom")
    kind = value["kind"]
    if kind != "custom":
        return Source(kind=kind)
    urls = {}
    for name in FILES:
        url = value.get(f"{name}_url")
        if not isinstance(url, str) or _URL.fullmatch(url.strip()) is None:
            raise GeodataError(f"{name}_url must be an https URL")
        urls[name] = url.strip()
    return Source(kind="custom", geosite_url=urls["geosite"], geoip_url=urls["geoip"])


def parse_interval(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not MIN_INTERVAL_HOURS <= value <= MAX_INTERVAL_HOURS:
        raise GeodataError(f"interval_hours must be {MIN_INTERVAL_HOURS}..{MAX_INTERVAL_HOURS}")
    return value


# ----------------------------------------------------------------- the .dat format

def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result, shift = 0, 0
    while True:
        if pos >= len(data):
            raise GeodataError("truncated geodata file", "geodata_corrupt")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise GeodataError("malformed geodata file", "geodata_corrupt")


def _skip(data: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:
        return _varint(data, pos)[1]
    if wire_type == 1:
        return pos + 8
    if wire_type == 2:
        length, pos = _varint(data, pos)
        return pos + length
    if wire_type == 5:
        return pos + 4
    raise GeodataError("malformed geodata file", "geodata_corrupt")


def parse_codes(data: bytes) -> list[str]:
    """The `country_code` of every entry of a `GeoSiteList` / `GeoIPList` (both are
    `repeated Entry entry = 1` with `string country_code = 1`), lower-cased and sorted —
    without decoding the domains or CIDRs themselves."""
    codes: set[str] = set()
    pos = 0
    while pos < len(data):
        key, pos = _varint(data, pos)
        field, wire_type = key >> 3, key & 7
        if field != 1 or wire_type != 2:
            pos = _skip(data, pos, wire_type)
            continue
        length, pos = _varint(data, pos)
        entry, pos = data[pos:pos + length], pos + length
        inner = 0
        while inner < len(entry):
            ikey, inner = _varint(entry, inner)
            ifield, itype = ikey >> 3, ikey & 7
            if ifield == 1 and itype == 2:
                size, inner = _varint(entry, inner)
                codes.add(entry[inner:inner + size].decode("utf-8", "replace").lower())
                inner += size
            else:
                inner = _skip(entry, inner, itype)
    if not codes:
        raise GeodataError("no entries in geodata file", "geodata_corrupt")
    return sorted(codes)


# ------------------------------------------------------------------- downloads

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str, *, max_bytes: int = MAX_FILE_BYTES, timeout: float = DOWNLOAD_TIMEOUT) -> tuple[bytes, str]:
    """The body of an HTTPS URL (redirects allowed, HTTPS end to end) and the final URL."""
    if _URL.fullmatch(url) is None:
        raise GeodataError("only https URLs are fetched", "geodata_invalid")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    hops: list[str] = []

    class _Hops(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            hops.append(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), _Hops())
    try:
        with opener.open(request, timeout=timeout) as response:
            final = response.geturl()
            if not final.startswith("https://") or any(not hop.startswith("https://") for hop in hops):
                raise GeodataError("redirected off https", "geodata_fetch_failed")
            data = response.read(max_bytes + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise GeodataError(f"fetch failed: {exc}"[:300], "geodata_fetch_failed") from exc
    if len(data) > max_bytes:
        raise GeodataError("file larger than the limit", "geodata_too_large")
    if not data:
        raise GeodataError("empty file", "geodata_fetch_failed")
    # GitHub's `releases/latest/download/…` names the release only on its first hop; the last
    # hop is a signed asset URL without it — report the hop that carries the release tag.
    final = next((hop for hop in hops if _RELEASE_TAG.search(hop)), final)
    return data, final


def download_pair(urls: dict[str, str], fetcher=fetch) -> dict[str, dict]:
    """Both files of a source: bytes, sha256, and — when `<url>.sha256sum` answers — the
    publisher's digest checked against ours. A sidecar that does not answer is not an error
    (a custom mirror may not publish one); a sidecar that disagrees is."""
    result = {}
    for name in FILES:
        data, final = fetcher(urls[name])
        digest = _sha256(data)
        published = None
        try:
            sidecar, _ = fetcher(urls[name] + ".sha256sum", max_bytes=4096)
            match = _SHA256.search(sidecar.decode("utf-8", "replace"))
            published = match.group(1).lower() if match else None
        except GeodataError:
            published = None
        if published is not None and published != digest:
            raise GeodataError(f"{name}.dat does not match its published sha256", "geodata_digest_mismatch")
        try:
            codes = parse_codes(data)
        except GeodataError as exc:
            raise GeodataError(f"{name}.dat: {exc}", exc.code) from exc
        tag = _RELEASE_TAG.search(final)
        result[name] = {"data": data, "sha256": digest, "size": len(data), "verified": published is not None,
                        "codes": codes, "version": tag.group(1) if tag else None, "url": final}
    return result


# ---------------------------------------------------------------------- store

class GeodataStore:
    """`<state>/geodata`: the two files Xray reads, `meta.json` beside them, the seed to fall
    back to. Swaps are atomic renames within the directory; the caller restarts Xray."""

    def __init__(self, directory: Path, seed: dict[str, Path], *, clock=None):
        import time as _time
        self.directory = Path(directory)
        self.seed = {name: Path(path) for name, path in seed.items()}
        self.clock = clock or _time
        self._codes_cache: dict[str, list[str]] = {}

    def path(self, name: str) -> Path:
        return self.directory / f"{name}.dat"

    def meta(self) -> dict:
        path = self.directory / "meta.json"
        default = {"source": Source("xray").wire(), "auto_update": False, "interval_hours": DEFAULT_INTERVAL_HOURS,
                   "origin": "seed", "version": None, "updated_at": None, "last_check_at": None, "last_error": None,
                   "files": {}}
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text())
        except ValueError:
            return default
        return {**default, **value} if isinstance(value, dict) else default

    def _write_meta(self, meta: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        _atomic_write(self.directory / "meta.json", json.dumps(meta, sort_keys=True, separators=(",", ":")).encode() + b"\n",
                      0o600)

    def _file_facts(self) -> dict[str, dict]:
        facts = {}
        for name in FILES:
            path = self.path(name)
            try:
                data = path.read_bytes()
            except OSError:
                facts[name] = {"sha256": None, "size": 0, "codes": 0}
                continue
            digest = _sha256(data)
            facts[name] = {"sha256": digest, "size": len(data), "codes": len(self._codes_for(name, digest, data))}
        return facts

    def _codes_for(self, name: str, digest: str, data: bytes | None = None) -> list[str]:
        key = f"{name}:{digest}"
        cached = self._codes_cache.get(key)
        if cached is None:
            if data is None:
                data = self.path(name).read_bytes()
            try:
                cached = parse_codes(data)
            except GeodataError:
                cached = []
            self._codes_cache = {key: cached, **{k: v for k, v in self._codes_cache.items() if k.split(":")[0] != name}}
        return cached

    def ensure_seed(self) -> bool:
        """Copy the pinned pair in when the directory has no files yet. True when it did."""
        if all(self.path(name).exists() for name in FILES):
            return False
        self.directory.mkdir(parents=True, exist_ok=True)
        for name in FILES:
            _atomic_write(self.path(name), self.seed[name].read_bytes(), 0o644)
        meta = self.meta()
        meta.update({"origin": "seed", "version": None, "updated_at": _now(self.clock), "last_error": None,
                     "files": self._file_facts()})
        self._write_meta(meta)
        return True

    def view(self) -> dict:
        meta = self.meta()
        return {**meta, "files": self._file_facts(), "seed": {name: {"sha256": _sha256_path(path)} for name, path in self.seed.items()},
                "limits": {"max_file_bytes": MAX_FILE_BYTES, "interval_hours": [MIN_INTERVAL_HOURS, MAX_INTERVAL_HOURS]}}

    def codes(self) -> dict[str, list[str]]:
        result = {}
        for name in FILES:
            try:
                data = self.path(name).read_bytes()
            except OSError:
                result[name] = []
                continue
            result[name] = self._codes_for(name, _sha256(data), data)
        return result

    def settings(self, *, source: Source | None = None, auto_update: bool | None = None,
                 interval_hours: int | None = None) -> dict:
        meta = self.meta()
        if source is not None:
            meta["source"] = source.wire()
        if auto_update is not None:
            meta["auto_update"] = bool(auto_update)
        if interval_hours is not None:
            meta["interval_hours"] = parse_interval(interval_hours)
        self._write_meta(meta)
        return self.view()

    def due(self) -> bool:
        meta = self.meta()
        if not meta.get("auto_update") or meta["source"]["kind"] == "xray":
            return False
        last = meta.get("last_check_at")
        if not last:
            return True
        return self.clock.time() - float(last) >= int(meta.get("interval_hours") or DEFAULT_INTERVAL_HOURS) * 3600

    def stage(self, fetcher=fetch) -> dict[str, dict] | None:
        """Download the source's pair into the directory under temporary names. None when the
        source is the seed (nothing to fetch) or the files already are what the source serves."""
        meta = self.meta()
        source = parse_source(meta["source"])
        urls = source.urls()
        if urls is None:
            return None
        downloaded = download_pair(urls, fetcher)
        current = self._file_facts()
        if all(current[name]["sha256"] == downloaded[name]["sha256"] for name in FILES):
            meta["last_check_at"] = self.clock.time()
            meta["last_error"] = None
            self._write_meta(meta)
            return None
        self.directory.mkdir(parents=True, exist_ok=True)
        staged = {}
        for name in FILES:
            fd, tmp = tempfile.mkstemp(prefix=f"{name}.", suffix=".dat.tmp", dir=self.directory)
            with os.fdopen(fd, "wb") as fh:
                fh.write(downloaded[name]["data"])
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o644)
            staged[name] = {**{k: v for k, v in downloaded[name].items() if k != "data"}, "tmp": Path(tmp)}
        return staged

    def discard(self, staged: dict[str, dict] | None) -> None:
        for entry in (staged or {}).values():
            Path(entry["tmp"]).unlink(missing_ok=True)

    def commit(self, staged: dict[str, dict], *, origin: str = "download") -> dict:
        for name in FILES:
            os.replace(staged[name]["tmp"], self.path(name))
        _fsync_directory(self.directory)
        meta = self.meta()
        versions = sorted(str(entry["version"]) for entry in staged.values() if entry.get("version"))
        meta.update({"origin": origin, "version": versions[0] if versions else None, "updated_at": _now(self.clock),
                     "last_check_at": self.clock.time(), "last_error": None, "files": self._file_facts()})
        self._write_meta(meta)
        return self.view()

    def restore_seed(self) -> dict:
        staged = {}
        for name in FILES:
            fd, tmp = tempfile.mkstemp(prefix=f"{name}.", suffix=".dat.tmp", dir=self.directory)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self.seed[name].read_bytes())
            os.chmod(tmp, 0o644)
            staged[name] = {"tmp": Path(tmp), "version": None}
        return self.commit(staged, origin="seed")

    def record_failure(self, exc: GeodataError) -> None:
        meta = self.meta()
        meta["last_check_at"] = self.clock.time()
        meta["last_error"] = f"{exc.code}: {exc}"[:300]
        self._write_meta(meta)

    def staged_dir(self, staged: dict[str, dict]) -> Path:
        """A directory Xray can be pointed at (`XRAY_LOCATION_ASSET`) to test the candidates:
        the staged files hard-linked under their final names."""
        directory = Path(tempfile.mkdtemp(prefix="geodata-test.", dir=self.directory))
        for name in FILES:
            os.link(staged[name]["tmp"], directory / f"{name}.dat")
        return directory


def _now(clock) -> str:
    import time as _time
    return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(clock.time()))


def _sha256_path(path: Path) -> str | None:
    try:
        return _sha256(path.read_bytes())
    except OSError:
        return None


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    _fsync_directory(path.parent)
