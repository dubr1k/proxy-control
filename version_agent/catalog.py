from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_COMPONENTS = ("telemt", "naive", "mita", "xray")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_VERSION = re.compile(r"^[^\r\n]{1,160}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$")
_ARCHIVE_FORMATS = ("zip", "tar.gz")
_MEMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SOURCES = ("catalog", "upstream")
XRAY_MEMBERS = ("xray", "geoip.dat", "geosite.dat")


class CatalogError(ValueError):
    """The trusted local catalog is malformed or contains an unsafe artifact."""


@dataclass(frozen=True)
class CatalogEntry:
    component: str
    version: str
    kind: str
    image: str | None = None
    url: str | None = None
    sha256: str | None = None
    runtime_version: str | None = None
    archive: dict | None = None
    source: str = "catalog"
    build: dict | None = None

    def public(self) -> dict:
        result = {"version": self.version, "kind": self.kind, "source": self.source}
        if self.image:
            result["image"] = self.image
        if self.url:
            # The URL is intentionally visible: it is an operator-approved source,
            # not a secret. The panel never accepts a URL from the browser.
            result["url"] = self.url
        if self.sha256:
            result["sha256"] = self.sha256
        if self.archive:
            result["archive"] = dict(self.archive)
        if self.build:
            result["build"] = dict(self.build)
        return result


@dataclass(frozen=True)
class Catalog:
    components: dict[str, tuple[CatalogEntry, ...]]

    def entry(self, component: str, version: str) -> CatalogEntry:
        for item in self.components.get(component, ()):
            if item.version == version:
                return item
        raise CatalogError(f"version is not approved for {component}")


def _reject_unknown(mapping: dict, allowed: set[str], label: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise CatalogError(f"unknown {label} field: {sorted(unknown)[0]}")


def _archive(component: str, raw: object) -> dict | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or raw.get("format") not in _ARCHIVE_FORMATS:
        raise CatalogError("unsupported archive format")
    _reject_unknown(raw, {"format", "member", "members"}, "archive")
    member = raw.get("member")
    members = raw.get("members")
    if (member is None) == (members is None):
        raise CatalogError("archive needs member or members")
    if component == "xray" and members is None:
        raise CatalogError("xray archive must name its members")
    if component != "xray" and members is not None:
        raise CatalogError(f"{component} archive must name a single member")
    if members is not None:
        if not isinstance(members, dict) or set(members) != set(XRAY_MEMBERS):
            raise CatalogError("invalid archive member set")
        names = list(members.values())
    else:
        names = [member]
    for name in names:
        if type(name) is not str or not _MEMBER.fullmatch(name) or ".." in name.split("/"):
            raise CatalogError("invalid archive member")
    if member is not None:
        return {"format": raw["format"], "member": member}
    return {"format": raw["format"], "members": dict(members)}


def _build(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise CatalogError("build entry must be an object")
    _reject_unknown(raw, {"caddy_version", "builder_image", "forwardproxy_commit"}, "build")
    version = raw.get("caddy_version")
    image = raw.get("builder_image")
    commit = raw.get("forwardproxy_commit")
    if (
        type(version) is not str
        or not _VERSION.fullmatch(version)
        or type(image) is not str
        or not _IMAGE.fullmatch(image)
        or not image.startswith("caddy:")
        or type(commit) is not str
        or not _HEX40.fullmatch(commit)
    ):
        raise CatalogError(
            "build entry must pin caddy_version, a caddy builder image digest and a forwardproxy commit"
        )
    return {"caddy_version": version, "builder_image": image, "forwardproxy_commit": commit}


def _entry(component: str, raw: object) -> CatalogEntry:
    if not isinstance(raw, dict):
        raise CatalogError(f"{component} catalog entry must be an object")
    _reject_unknown(
        raw,
        {"version", "kind", "image", "url", "sha256", "runtime_version", "archive", "source", "build"},
        "catalog",
    )
    version = raw.get("version")
    kind = raw.get("kind")
    if type(version) is not str or not _VERSION.fullmatch(version):
        raise CatalogError(f"invalid version for {component}")
    runtime_version = raw.get("runtime_version")
    if runtime_version is not None and (
        type(runtime_version) is not str or not _RUNTIME_VERSION.fullmatch(runtime_version)
    ):
        raise CatalogError(f"invalid runtime_version for {component}")
    source = raw.get("source", "catalog")
    if source not in _SOURCES:
        raise CatalogError(f"invalid source for {component}")
    if kind == "image":
        _reject_unknown(raw, {"version", "kind", "image", "runtime_version", "source"}, "image")
        image = raw.get("image")
        if type(image) is not str or not _IMAGE.fullmatch(image):
            raise CatalogError("telemt image must use an immutable image digest")
        return CatalogEntry(
            component, version, kind, image=image, runtime_version=runtime_version, source=source
        )
    if kind == "binary":
        _reject_unknown(
            raw, {"version", "kind", "url", "sha256", "runtime_version", "archive", "source"}, "binary"
        )
        url = raw.get("url")
        digest = raw.get("sha256")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise CatalogError("binary artifact URL must be HTTPS without credentials or query")
        if type(digest) is not str or not _SHA256.fullmatch(digest):
            raise CatalogError("binary artifact must have a lowercase SHA-256")
        return CatalogEntry(
            component,
            version,
            kind,
            url=url,
            sha256=digest,
            runtime_version=runtime_version,
            archive=_archive(component, raw.get("archive")),
            source=source,
        )
    if kind == "build" and component == "naive":
        _reject_unknown(raw, {"version", "kind", "build", "runtime_version", "source"}, "build")
        return CatalogEntry(
            component,
            version,
            kind,
            runtime_version=runtime_version,
            source=source,
            build=_build(raw.get("build")),
        )
    raise CatalogError(f"unsupported artifact kind for {component}")


def entry_from_dict(component: str, raw: object) -> CatalogEntry:
    """Validate one entry the way the catalog does (used for cached upstream candidates)."""
    if component not in _COMPONENTS:
        raise CatalogError("unknown version catalog component")
    return _entry(component, raw)


def load_catalog(path: Path) -> Catalog:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError("version catalog unavailable") from exc
    if not isinstance(raw, dict):
        raise CatalogError("version catalog must be an object")
    _reject_unknown(raw, {"schema", "components"}, "catalog root")
    if raw.get("schema") != 1 or not isinstance(raw.get("components"), dict):
        raise CatalogError("unsupported version catalog schema")
    if set(raw["components"]) - set(_COMPONENTS):
        raise CatalogError("unknown version catalog component")
    result: dict[str, tuple[CatalogEntry, ...]] = {}
    for component in _COMPONENTS:
        values = raw["components"].get(component, [])
        if not isinstance(values, list):
            raise CatalogError(f"{component} catalog must be a list")
        entries = tuple(_entry(component, value) for value in values)
        versions = [item.version for item in entries]
        if len(set(versions)) != len(versions):
            raise CatalogError(f"duplicate {component} version")
        result[component] = entries
    return Catalog(result)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
