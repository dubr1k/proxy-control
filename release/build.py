#!/usr/bin/env python3
"""Build one reproducible Proxy Control release from tracked deployment inputs.

`release/runtime-files.json` selects the user payload, not the source/build tree.
Shipped Markdown links to omitted tracked files point at the exact source commit.
Two builds of the same commit produce byte-identical outputs: the archive is
assembled from selected `git ls-files -z` paths in sorted order, every member is owned by
`root:root` with uid/gid zero, the mode comes from the Git executable bit
alone, and every mtime is the release commit timestamp.  Untracked, ignored,
private, and lab state never enters the archive.

The prebuilt host binaries (`release/host-binaries.list`) are the one exception to
"tracked files only": they are built from tracked crates by the pinned builder image
(`release/Dockerfile.host-binaries`), checked against the digests the builder recorded,
and injected with mode 0755 the way `release/release.json` and the SBOM are injected.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

RELEASE_SCHEMA = 1
ARCHIVE_PREFIX = "proxy-control"
IDENTITY_NAME = "release/release.json"
MANIFEST_NAME = "release-manifest.json"
SBOM_NAME = "sbom.spdx.json"
CHECKSUM_NAME = "SHA256SUMS"
# The install script published beside the archive: the repository's
# scripts/install-release.sh with this release's version and archive digest stamped in,
# so `bash install-release.sh` installs exactly these bytes. Its digest goes to a file of
# its own — SHA256SUMS keeps naming the three files that `install-release.sh` copies of
# earlier releases check with `--check --strict`.
INSTALLER_SOURCE = "scripts/install-release.sh"
INSTALLER_NAME = "install-release.sh"
INSTALLER_CHECKSUM_NAME = "install-release.sh.sha256"
_STAMP_VERSION = 'STAMPED_VERSION=""'
_STAMP_SHA256 = 'STAMPED_SHA256=""'

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

# Prebuilt host binaries. The list names the crates; a crate takes part once its Cargo.toml is
# tracked. The builder writes each binary at <crate>/bin/linux-amd64/<name> plus two files of its
# own: the sha256sum lines of every binary and the builder identity (image, target, rustc).
HOST_BINARIES_LIST = "release/host-binaries.list"
HOST_BINARIES_DOCKERFILE = "release/Dockerfile.host-binaries"
HOST_BINARY_DIGESTS = "host-binaries.sha256"
HOST_BINARY_BUILDER = "host-binaries.builder"
HOST_TARGET = "x86_64-unknown-linux-musl"
HOST_PLATFORM_DIR = "bin/linux-amd64"
# Compile-time resources must be tracked, even when they live inside a crate.
# Neither the workstation nor a cache may supply a missing declared input.
HOST_BINARY_EMBEDDED_INPUTS = {
    "installer": ("installer/assets/three-xui-api-contract-3.10.2.json",),
}
DISTRIBUTION_POLICY = "release/runtime-files.json"
_CRATE_DIR_RE = re.compile(r"[a-z0-9_][a-z0-9_-]*(?:/[a-z0-9_][a-z0-9_-]*)*\Z")
_BINARY_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_BUILDER_IMAGE_RE = re.compile(r"^ARG BUILDER_IMAGE=(\S+@sha256:[0-9a-f]{64})$", re.M)
_DIGEST_LINE_RE = re.compile(r"([0-9a-f]{64})  (\S+)\Z")
_CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


class ReleaseBuildError(RuntimeError):
    """The release cannot be built reproducibly from this source tree."""


@dataclass(frozen=True)
class HostCrates:
    """The crates of `release/host-binaries.list` that exist in the tracked tree."""

    libraries: tuple[str, ...] = ()
    binaries: tuple[tuple[str, str], ...] = ()  # (crate dir, binary name)

    @property
    def directories(self) -> tuple[str, ...]:
        return (*self.libraries, *(crate for crate, _ in self.binaries))

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(sorted(host_binary_path(crate, binary) for crate, binary in self.binaries))


@dataclass(frozen=True)
class HostBinaries:
    """Built host binaries, keyed by their path inside the release tree."""

    files: Mapping[str, bytes] = field(default_factory=dict)
    builder: Mapping[str, str] = field(default_factory=dict)

    def digests(self) -> dict[str, str]:
        return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(self.files.items())}


def host_binary_path(crate: str, binary: str) -> str:
    return f"{crate}/{HOST_PLATFORM_DIR}/{binary}"

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
    installer: Path | None = None


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


# Tracked for the people and agents who work on the repository, never shipped: the project's
# knowledge graph (`graphify update .`) is tens of megabytes no node needs.
OMITTED_TOP_LEVEL = frozenset({"graphify-out"})


def tracked_files(source: Path) -> tuple[str, ...]:
    """Every tracked path, sorted, with the forbidden ones refused and the omitted ones left out."""
    raw = _git(source, "ls-files", "-z")
    names = tuple(sorted(name for name in raw.split("\0") if name and name.split("/", 1)[0] not in OMITTED_TOP_LEVEL))
    if not names:
        raise ReleaseBuildError("the source tree tracks no files")
    root = source.resolve()
    for name in names:
        top = name.split("/", 1)[0]
        if top in FORBIDDEN_TOP_LEVEL:
            raise ReleaseBuildError(f"a release must not contain {top}")
        if name.endswith(FORBIDDEN_SUFFIXES):
            raise ReleaseBuildError(f"a release must not contain {name}")
        path = source / name
        if path.is_symlink() or path.resolve() != root / name:
            raise ReleaseBuildError(f"a release must not read a symlinked source path: {name}")
    return names


def _path_matches(name: str, pattern: str) -> bool:
    """POSIX path globs: * stays in one component, ** spans zero or more."""
    parts, rules = name.split("/"), pattern.split("/")

    def match(i: int, j: int) -> bool:
        if j == len(rules):
            return i == len(parts)
        if rules[j] == "**":
            return match(i, j + 1) or (i < len(parts) and match(i + 1, j))
        return i < len(parts) and fnmatch.fnmatchcase(parts[i], rules[j]) and match(i + 1, j + 1)

    return match(0, 0)


def distribution_files(source: Path, names: Sequence[str]) -> tuple[str, ...]:
    """Select payload files, independently of the complete tracked build inputs."""
    if DISTRIBUTION_POLICY not in names:
        raise ReleaseBuildError(f"{DISTRIBUTION_POLICY} must be tracked")
    try:
        policy = json.loads((source / DISTRIBUTION_POLICY).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseBuildError(f"invalid {DISTRIBUTION_POLICY}") from exc
    if (not isinstance(policy, dict) or set(policy) != {"schema", "include", "exclude"}
            or type(policy.get("schema")) is not int or policy["schema"] != 1):
        raise ReleaseBuildError(f"invalid {DISTRIBUTION_POLICY} schema")
    for kind in ("include", "exclude"):
        rules = policy[kind]
        if not isinstance(rules, list) or (kind == "include" and not rules):
            raise ReleaseBuildError(f"invalid {DISTRIBUTION_POLICY} {kind}")
        for rule in rules:
            if (not isinstance(rule, str) or not rule or rule.startswith("/")
                    or "\\" in rule or any(ord(c) < 32 for c in rule)
                    or any(part in {"", ".", ".."} for part in rule.split("/"))):
                raise ReleaseBuildError(f"unsafe {DISTRIBUTION_POLICY} pattern")
    selected = tuple(name for name in names
                     if any(_path_matches(name, rule) for rule in policy["include"])
                     and not any(_path_matches(name, rule) for rule in policy["exclude"]))
    for required in ("VERSION", "install.sh", INSTALLER_SOURCE, "release/external-artifacts.json"):
        if required not in selected:
            raise ReleaseBuildError(f"{DISTRIBUTION_POLICY} omits required {required}")
    return selected


def distribution_document(name: str, data: bytes, *, selected: set[str], tracked: set[str], commit: str) -> bytes:
    """Keep shipped Markdown usable without shipping its development link targets."""
    if not name.endswith(".md"):
        return data
    directory = posixpath.dirname(name)

    def target(raw: str) -> str:
        parts = raw.split(maxsplit=1)
        if not parts:
            return raw
        original = parts[0].strip("<>")
        parsed = urlsplit(original)
        if parsed.scheme or parsed.netloc or not parsed.path or original.startswith(("#", "/")):
            return raw
        path = posixpath.normpath(posixpath.join(directory, unquote(parsed.path)))
        if path.startswith("../") or path == "..":
            return raw
        prefix = path.rstrip("/") + "/"
        if path in selected or any(p.startswith(prefix) for p in selected):
            return raw
        is_file = path in tracked
        if not is_file and not any(p.startswith(prefix) for p in tracked):
            return raw
        kind = "blob" if is_file else "tree"
        url = f"https://github.com/dubr1k/proxy-control/{kind}/{commit}/{quote(path, safe='/')}"
        result = urlunsplit((*urlsplit(url)[:3], parsed.query, parsed.fragment))
        return result + (" " + parts[1] if len(parts) > 1 else "")

    def links(text: str) -> str:
        text = re.sub(r"\]\(([^)\n]+)\)", lambda m: "](" + target(m[1]) + ")", text)
        return re.sub(r"^( {0,3}\[[^]\n]+\]:[ \t]*)(\S+)",
                      lambda m: m[1] + target(m[2]), text, flags=re.M)

    def prose(text: str) -> str:
        # Exact-length backtick runs, including multiline/double-backtick spans.
        spans = re.finditer(r"(?<!`)(`+)(?!`)(.*?)(?<!`)\1(?!`)|<code\b[^>]*>.*?</code\s*>", text, re.S | re.I)
        pieces, offset = [], 0
        for span in spans:
            pieces.extend((links(text[offset:span.start()]), span[0]))
            offset = span.end()
        pieces.append(links(text[offset:]))
        return "".join(pieces)

    lines: list[str] = []
    pending: list[str] = []
    fence: tuple[str, int] | None = None
    raw_end: str | None = None

    def flush() -> None:
        lines.append(prose("".join(pending)))
        pending.clear()

    for line in data.decode("utf-8").splitlines(keepends=True):
        context, depth = line, 0
        while prefix := re.match(r" {0,3}>[ \t]?", context):
            context = context[prefix.end():]
            depth += 1
        if fence and depth < fence[1]:
            fence = None  # A fenced block cannot escape its containing blockquote.
        if raw_end:
            lines.append(line)
            if re.search(raw_end, context, re.I):
                raw_end = None
            continue
        if fence:
            lines.append(line)
            token = fence[0]
            if re.fullmatch(r" {0,3}" + re.escape(token[0]) + "{" + str(len(token)) + r",}[ \t]*\r?\n?", context):
                fence = None  # A closing fence has no info string or trailing text.
            continue
        if re.match(r"(?: {4}|\t)", context):
            flush()
            lines.append(line)
            continue
        stripped = context.lstrip()
        # Recognize fenced blocks in lists as well as at the top level/in quotes.
        opening = re.sub(r"^(?:[-+*]|[0-9]+[.)])[ \t]+", "", stripped)
        marker = re.match(r"(`{3,}|~{3,})", opening)
        tag = re.match(r"<(pre|script|style|textarea)(?:\s|>)", stripped, re.I)
        if marker:
            flush()
            fence = marker[1], depth
            lines.append(line)
        elif tag or stripped.startswith("<!--"):
            flush()
            end = rf"</{tag[1]}\s*>" if tag else "-->"
            raw_end = None if re.search(end, stripped, re.I) else end
            lines.append(line)
        elif not line.strip():
            flush()  # Inline code cannot span separate paragraphs or blocks.
            lines.append(line)
        else:
            pending.append(line)
    flush()
    return "".join(lines).encode("utf-8")


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
    binaries: HostBinaries | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "artifacts": dict(sorted(artifacts.items())),
        "commit": commit,
        "components": dict(sorted(components.items())),
        "manifest_sha256": manifest_sha256,
        "schema": RELEASE_SCHEMA,
        "tag": f"v{version}",
        "version": version,
    }
    # Additive (schema stays 1): readers of release.json ignore keys they do not know, and a
    # release without host binaries keeps the exact bytes it had before they existed.
    if binaries is not None and binaries.files:
        document["binaries"] = binaries.digests()
        document["builder"] = dict(sorted(binaries.builder.items()))
    return document


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


def stamp_installer(script: bytes, *, version: str, archive_sha256: str) -> bytes:
    """The published copy of the install script: the two empty stamps filled in."""
    text = script.decode("utf-8")
    for stamp in (_STAMP_VERSION, _STAMP_SHA256):
        if text.count(f"\n{stamp}\n") != 1:
            raise ReleaseBuildError(f"{INSTALLER_SOURCE} must carry the line {stamp} exactly once")
    if re.fullmatch(r"[0-9a-f]{64}", archive_sha256) is None:
        raise ReleaseBuildError("the archive digest to stamp is not a SHA-256")
    text = text.replace(f"\n{_STAMP_VERSION}\n", f'\nSTAMPED_VERSION="{version}"\n')
    text = text.replace(f"\n{_STAMP_SHA256}\n", f'\nSTAMPED_SHA256="{archive_sha256}"\n')
    return text.encode("utf-8")


def _stamps(script: bytes) -> tuple[str, str]:
    text = script.decode("utf-8")
    version = re.search(r'^STAMPED_VERSION="([^"]*)"$', text, re.M)
    digest = re.search(r'^STAMPED_SHA256="([^"]*)"$', text, re.M)
    if version is None or digest is None:
        raise ReleaseBuildError(f"{INSTALLER_NAME} carries no release stamps")
    return version.group(1), digest.group(1)


# ----------------------------------------------------------------------
# prebuilt host binaries
# ----------------------------------------------------------------------


def host_crates(source: Path, names: Sequence[str]) -> HostCrates:
    """The listed crates whose Cargo.toml is tracked; a tree without the list has none."""
    tracked = set(names)
    if HOST_BINARIES_LIST not in tracked:
        return HostCrates()
    libraries: list[str] = []
    binaries: list[tuple[str, str]] = []
    seen: set[str] = set()
    text = (source / HOST_BINARIES_LIST).read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        where = f"{HOST_BINARIES_LIST}:{number}"
        if fields[0] == "lib" and len(fields) == 2:
            crate, binary = fields[1], None
        elif fields[0] == "bin" and len(fields) == 3:
            crate, binary = fields[1], fields[2]
            if _BINARY_NAME_RE.fullmatch(binary) is None:
                raise ReleaseBuildError(f"{where}: {binary!r} is not a binary name")
        else:
            raise ReleaseBuildError(f"{where}: expected 'lib <crate>' or 'bin <crate> <binary>'")
        if _CRATE_DIR_RE.fullmatch(crate) is None:
            raise ReleaseBuildError(f"{where}: {crate!r} is not a crate directory")
        if crate in seen:
            raise ReleaseBuildError(f"{where}: {crate} is listed twice")
        seen.add(crate)
        if f"{crate}/Cargo.toml" not in tracked:
            continue
        if binary is None:
            libraries.append(crate)
            continue
        if f"{crate}/Cargo.lock" not in tracked:
            raise ReleaseBuildError(f"{crate} builds a host binary but tracks no Cargo.lock")
        path = host_binary_path(crate, binary)
        if any(name == path or name.startswith(f"{crate}/{HOST_PLATFORM_DIR}/") for name in tracked):
            raise ReleaseBuildError(f"{crate}/{HOST_PLATFORM_DIR}/ must not be tracked: the release builds {path}")
        binaries.append((crate, binary))
    return HostCrates(tuple(libraries), tuple(binaries))


def builder_image(source: Path) -> str:
    """The pinned builder image, read from the Dockerfile's `ARG BUILDER_IMAGE=` line."""
    try:
        text = (source / HOST_BINARIES_DOCKERFILE).read_text(encoding="utf-8")
    except OSError as exc:
        raise ReleaseBuildError(f"{HOST_BINARIES_DOCKERFILE} is unreadable") from exc
    found = _BUILDER_IMAGE_RE.findall(text)
    if len(found) != 1:
        raise ReleaseBuildError(f"{HOST_BINARIES_DOCKERFILE} must pin exactly one BUILDER_IMAGE by digest")
    return found[0]


def _run_builder(command: Sequence[str]) -> None:
    """Run the container build; its progress goes to stderr so stdout stays the digest lines."""
    try:
        subprocess.run(tuple(command), check=True, stdout=2)
    except OSError as exc:
        raise ReleaseBuildError("docker is not available to build the host binaries") from exc
    except subprocess.CalledProcessError as exc:
        raise ReleaseBuildError(f"the host binaries did not build (docker exited {exc.returncode})") from exc


def build_host_binaries(source: Path, names: Sequence[str], destination: Path, *, epoch: int) -> None:
    """Build the listed host crates with the pinned builder into `destination`.

    The build context is staged from tracked files only (VERSION, the list, every
    listed crate and its declared embedded inputs) and built with no layer cache,
    so every build starts from the image and Cargo.lock alone."""
    crates = host_crates(source, names)
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ReleaseBuildError(f"{destination} must be empty to receive the host binaries")
    prefixes = tuple(f"{crate}/" for crate in crates.directories)
    embedded_inputs = {
        name for crate in crates.directories for name in HOST_BINARY_EMBEDDED_INPUTS.get(crate, ())
    }
    missing = embedded_inputs - set(names)
    if missing:
        raise ReleaseBuildError(f"required build input {sorted(missing)[0]} must be tracked")
    root_inputs = {"VERSION", HOST_BINARIES_LIST} | embedded_inputs
    wanted = [name for name in names if name in root_inputs or name.startswith(prefixes)]
    with tempfile.TemporaryDirectory(prefix="proxy-control-host-binaries-") as staging:
        context = Path(staging) / "context"
        for name in wanted:
            target = context / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / name).read_bytes())
        dockerfile = Path(staging) / "Dockerfile.host-binaries"
        dockerfile.write_bytes((source / HOST_BINARIES_DOCKERFILE).read_bytes())
        _run_builder(
            (
                "docker", "buildx", "build",
                "--no-cache",
                "--platform", "linux/amd64",
                "--file", str(dockerfile),
                "--build-arg", f"SOURCE_DATE_EPOCH={int(epoch)}",
                "--target", "binaries",
                "--output", f"type=local,dest={destination}",
                str(context),
            )
        )


def load_host_binaries(directory: Path, *, expected: Sequence[str], image: str) -> HostBinaries:
    """Read built host binaries back, refusing anything but exactly `expected`, intact.

    `directory` is the builder's output: each binary at its release path, the sha256sum
    lines the builder wrote, and the builder identity, which must name the pinned image."""
    directory = Path(directory)
    try:
        listing = (directory / HOST_BINARY_DIGESTS).read_text(encoding="utf-8")
        identity = (directory / HOST_BINARY_BUILDER).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReleaseBuildError(f"{directory} is not a host binary build (no {HOST_BINARY_DIGESTS})") from exc
    recorded: dict[str, str] = {}
    for line in listing.splitlines():
        match = _DIGEST_LINE_RE.fullmatch(line)
        if match is None or match.group(2) in recorded:
            raise ReleaseBuildError(f"{HOST_BINARY_DIGESTS} has a malformed line: {line!r}")
        recorded[match.group(2)] = match.group(1)
    builder: dict[str, str] = {}
    for line in identity.splitlines():
        key, _, value = line.partition(" ")
        builder[key] = value
    if builder.get("image") != image:
        raise ReleaseBuildError(f"the host binaries were built by {builder.get('image')!r}, not the pinned {image}")
    if builder.get("target") != HOST_TARGET:
        raise ReleaseBuildError(f"the host binaries target {builder.get('target')!r}, not {HOST_TARGET}")
    if not builder.get("rustc", "").startswith("rustc "):
        raise ReleaseBuildError(f"{HOST_BINARY_BUILDER} does not name the compiler")
    wanted = set(expected)
    for name in sorted(wanted - set(recorded)):
        raise ReleaseBuildError(f"the host binary {name} is missing from {directory}")
    present = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if not path.is_dir() or path.is_symlink()
    } - {HOST_BINARY_DIGESTS, HOST_BINARY_BUILDER}
    for name in sorted((set(recorded) | present) - wanted):
        raise ReleaseBuildError(f"{directory} carries {name}, which is not a host binary of this tree")
    files: dict[str, bytes] = {}
    for name in sorted(wanted):
        path = directory / name
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise ReleaseBuildError(f"the host binary {name} is missing from {directory}") from exc
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseBuildError(f"the host binary {name} is not a regular file")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != recorded[name]:
            raise ReleaseBuildError(f"the host binary {name} does not match {HOST_BINARY_DIGESTS}")
        files[name] = data
    return HostBinaries(
        files=files,
        builder={"image": image, "rustc": builder["rustc"], "target": HOST_TARGET},
    )


def host_crate_packages(source: Path, crates: HostCrates) -> list[dict[str, str]]:
    """Every registry crate the host binaries' Cargo.lock files pin, for the SBOM.

    Path dependencies are files of the archive already; anything fetched from elsewhere
    than crates.io is refused, because its bytes would not be pinned by a checksum."""
    packages: dict[tuple[str, str], str] = {}
    for crate, _binary in crates.binaries:
        try:
            lock = tomllib.loads((source / crate / "Cargo.lock").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise ReleaseBuildError(f"{crate}/Cargo.lock is unreadable") from exc
        for package in lock.get("package", []):
            origin = package.get("source")
            if origin is None:
                continue
            name, version = str(package.get("name", "")), str(package.get("version", ""))
            checksum = package.get("checksum")
            if origin != _CRATES_IO or not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                raise ReleaseBuildError(f"{crate}/Cargo.lock pins {name} {version} from {origin} without a crates.io checksum")
            packages[(name, version)] = checksum
    return [
        {"name": name, "version": version, "checksum": checksum}
        for (name, version), checksum in sorted(packages.items())
    ]


def verify_archive_binaries(archive: Path) -> dict[str, str]:
    """Every binary `release/release.json` records is a 0755 member with that digest."""
    with tarfile.open(archive, mode="r:gz") as handle:
        identity_member = handle.extractfile(f"{ARCHIVE_PREFIX}/{IDENTITY_NAME}")
        if identity_member is None:
            raise ReleaseBuildError(f"the archive carries no {IDENTITY_NAME}")
        recorded = json.loads(identity_member.read()).get("binaries", {})
        for name, digest in sorted(recorded.items()):
            try:
                member = handle.getmember(f"{ARCHIVE_PREFIX}/{name}")
            except KeyError as exc:
                raise ReleaseBuildError(f"the archive lacks the host binary {name}") from exc
            extracted = handle.extractfile(member) if member.isreg() else None
            if extracted is None or member.mode != 0o755:
                raise ReleaseBuildError(f"the host binary {name} is not a 0755 regular file")
            if hashlib.sha256(extracted.read()).hexdigest() != digest:
                raise ReleaseBuildError(f"the host binary {name} does not match {IDENTITY_NAME}")
    return dict(recorded)


def build_release(
    output: Path,
    *,
    source: Path,
    version: str,
    commit: str | None = None,
    epoch: int | None = None,
    require_clean: bool = True,
    binaries_from: Path | None = None,
    binaries: bool = True,
) -> BuiltRelease:
    """Build the archive, checksums, manifest, and SBOM into `output`.

    Host binaries: with `binaries_from` the already-built bytes in that directory are
    checked and injected; otherwise the pinned builder builds them (Docker); with
    `binaries=False` they are left out (unit tests, dry runs: such an archive does not
    install a release whose host crates exist)."""
    if binaries_from is not None and not binaries:
        raise ReleaseBuildError("--binaries-from and --no-binaries exclude each other")
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
    if (source / "panel" / "Cargo.toml").is_file():
        generation = source / "pc_common" / "RELEASE"
        if not generation.is_file() or generation.read_bytes() != (source / "VERSION").read_bytes():
            raise ReleaseBuildError("pc_common/RELEASE must match VERSION for the Rust panel build guard")
    timestamp = epoch if epoch is not None else commit_epoch(source, resolved)
    names = tracked_files(source)
    shipped = distribution_files(source, names)

    crates = host_crates(source, names)
    host: HostBinaries | None = None
    if binaries and (crates.binaries or binaries_from is not None):
        image = builder_image(source)
        if binaries_from is not None:
            host = load_host_binaries(binaries_from, expected=crates.paths, image=image)
        else:
            with tempfile.TemporaryDirectory(prefix="proxy-control-host-out-") as built:
                build_host_binaries(source, names, Path(built) / "out", epoch=timestamp)
                host = load_host_binaries(Path(built) / "out", expected=crates.paths, image=image)

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
            binaries=host,
        )
    )

    if __package__:
        from release.sbom import build_sbom
    else:  # running the file directly, without the package on sys.path
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from sbom import build_sbom  # type: ignore[no-redef]

    payloads: dict[str, bytes] = {}
    selected, tracked = set(shipped), set(names)
    for name in shipped:
        if name == IDENTITY_NAME:
            continue
        payloads[name] = distribution_document(
            name, (source / name).read_bytes(), selected=selected, tracked=tracked, commit=resolved,
        )
    payloads[IDENTITY_NAME] = identity
    # The host binaries join before the SBOM, so it lists each with its digest, and the
    # registry crates linked into them become packages of their own.
    host_files = dict(host.files) if host is not None else {}
    payloads.update(host_files)
    executables = set(host_files)
    crate_packages = host_crate_packages(source, crates) if executables else []

    sbom = build_sbom(
        version=version,
        commit=resolved,
        files={name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()},
        external=source / "release" / "external-artifacts.json",
        epoch=timestamp,
        crates=crate_packages,
    )
    payloads[f"release/{SBOM_NAME}"] = sbom

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"{ARCHIVE_PREFIX}-v{version}.tar.gz"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as handle:
        for name in sorted(payloads):
            data = payloads[name]
            executable = name in executables or (name in names and _executable(source, name))
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

    if INSTALLER_SOURCE not in payloads:
        raise ReleaseBuildError(f"{INSTALLER_SOURCE} is not a tracked file")
    installer_bytes = stamp_installer(payloads[INSTALLER_SOURCE], version=version, archive_sha256=archive_sha256)
    installer = output / INSTALLER_NAME
    installer.write_bytes(installer_bytes)
    installer.chmod(0o755)
    (output / INSTALLER_CHECKSUM_NAME).write_text(
        f"{hashlib.sha256(installer_bytes).hexdigest()}  {INSTALLER_NAME}\n"
    )

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
        installer=installer,
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
    # The published install script: its own checksum file, and stamps naming exactly
    # this release and this archive.
    installer = dist / INSTALLER_NAME
    installer_bytes = installer.read_bytes()
    value, _, name = (dist / INSTALLER_CHECKSUM_NAME).read_text().strip().partition("  ")
    if name != INSTALLER_NAME or value != hashlib.sha256(installer_bytes).hexdigest():
        raise ReleaseBuildError(f"{INSTALLER_NAME} does not match {INSTALLER_CHECKSUM_NAME}")
    if _stamps(installer_bytes) != (str(manifest["version"]), digest):
        raise ReleaseBuildError(f"{INSTALLER_NAME} is stamped for another release")
    verify_archive_binaries(archive)
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
        installer=installer,
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
    host = parser.add_mutually_exclusive_group()
    host.add_argument(
        "--binaries-from",
        type=Path,
        metavar="DIR",
        help="inject host binaries already built into DIR (by --build-binaries) after checking their digests",
    )
    host.add_argument(
        "--no-binaries",
        action="store_true",
        help="leave the host binaries out (tests and dry runs; the archive cannot install host crates)",
    )
    host.add_argument(
        "--build-binaries",
        type=Path,
        metavar="DIR",
        help="only build the host binaries into the empty DIR and print their digests",
    )
    arguments = parser.parse_args(argv)
    try:
        if arguments.verify is not None:
            built = verify_release(arguments.verify)
            print(f"verified {built.archive.name} {built.archive_sha256}")
            return 0
        if arguments.build_binaries is not None:
            source = Path(arguments.source)
            if not arguments.allow_dirty:
                assert_clean(source)
            names = tracked_files(source)
            commit = (arguments.commit or _git(source, "rev-parse", "HEAD").strip()).lower()
            epoch = arguments.epoch if arguments.epoch is not None else commit_epoch(source, commit)
            build_host_binaries(source, names, arguments.build_binaries, epoch=epoch)
            built_binaries = load_host_binaries(
                arguments.build_binaries, expected=host_crates(source, names).paths, image=builder_image(source)
            )
            for name, digest in built_binaries.digests().items():
                print(f"{digest}  {name}")
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
            binaries_from=arguments.binaries_from,
            binaries=not arguments.no_binaries,
        )
    except (ReleaseBuildError, OSError, ValueError) as exc:
        print(f"RELEASE FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"{built.archive_sha256}  {built.archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
