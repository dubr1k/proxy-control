#!/usr/bin/env python3
"""Deterministic SPDX 2.3 JSON for one Proxy Control release.

The document lists every packaged file with its SHA-256, every pinned external
artifact with its licence and digest, and the relationships between them.  It
contains no timestamp other than the release commit's, so two builds of the
same commit produce identical bytes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
NAMESPACE = "https://github.com/dubr1k/proxy-control/spdx"
_SAFE_ID = re.compile(r"[^A-Za-z0-9.-]")


class SbomError(ValueError):
    """The SBOM cannot be generated from these inputs."""


def _identifier(prefix: str, value: str) -> str:
    return f"SPDXRef-{prefix}-{_SAFE_ID.sub('-', value)}"


def _external_packages(external: Path) -> list[dict[str, object]]:
    try:
        document = json.loads(Path(external).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SbomError("the external artifact manifest is unreadable") from exc
    packages: list[dict[str, object]] = []
    for entry in document.get("artifacts", []):
        if not isinstance(entry, Mapping):
            continue
        name = str(entry.get("name", ""))
        version = str(entry.get("version", ""))
        licence = str(entry.get("spdx_license", "NOASSERTION"))
        repository = str(entry.get("repository", ""))
        for architecture, pin in sorted(entry.get("platforms", {}).items()):
            if not isinstance(pin, Mapping):
                continue
            checksums = [
                {"algorithm": "SHA256", "checksumValue": str(pin["sha256"])}
            ]
            if isinstance(pin.get("executable_sha256"), str):
                checksums.append(
                    {
                        "algorithm": "SHA256",
                        "checksumValue": str(pin["executable_sha256"]),
                    }
                )
            packages.append(
                {
                    "SPDXID": _identifier("Package", f"{name}-{architecture}"),
                    "checksums": checksums,
                    "downloadLocation": str(pin.get("url", "NOASSERTION")),
                    "filesAnalyzed": False,
                    "licenseConcluded": licence,
                    "licenseDeclared": licence,
                    "name": f"{name}-{architecture}",
                    "supplier": (
                        f"Organization: {repository}" if repository else "NOASSERTION"
                    ),
                    "versionInfo": version,
                }
            )
    return packages


def build_sbom(
    *,
    version: str,
    commit: str,
    files: Mapping[str, str],
    external: Path,
    epoch: int,
) -> bytes:
    """Render the SPDX document as canonical bytes."""
    if not files:
        raise SbomError("a release SBOM needs at least one packaged file")
    created = datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    root_id = "SPDXRef-Package-proxy-control"
    file_entries = [
        {
            "SPDXID": _identifier("File", name),
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            "fileName": f"./{name}",
            "licenseConcluded": "NOASSERTION",
        }
        for name, digest in sorted(files.items())
    ]
    external_packages = _external_packages(external)
    relationships: list[dict[str, object]] = [
        {
            "relatedSpdxElement": root_id,
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
    ]
    relationships.extend(
        {
            "relatedSpdxElement": entry["SPDXID"],
            "relationshipType": "CONTAINS",
            "spdxElementId": root_id,
        }
        for entry in file_entries
    )
    relationships.extend(
        {
            "relatedSpdxElement": package["SPDXID"],
            "relationshipType": "DEPENDS_ON",
            "spdxElementId": root_id,
        }
        for package in external_packages
    )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: proxy-control-release-builder"],
        },
        "dataLicense": DATA_LICENSE,
        "documentNamespace": f"{NAMESPACE}/v{version}-{commit}",
        "files": file_entries,
        "name": f"proxy-control-v{version}",
        "packages": [
            {
                "SPDXID": root_id,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "name": "proxy-control",
                "versionInfo": version,
            },
            *external_packages,
        ],
        "relationships": relationships,
        "spdxVersion": SPDX_VERSION,
    }
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--external", type=Path, required=True)
    parser.add_argument("--file", action="append", default=[], metavar="NAME=SHA256")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    files: dict[str, str] = {}
    for item in arguments.file:
        name, _, digest = item.partition("=")
        files[name] = digest
    try:
        document = build_sbom(
            version=arguments.version,
            commit=arguments.commit,
            files=files,
            external=arguments.external,
            epoch=arguments.epoch,
        )
    except SbomError as exc:
        print(f"SBOM FAILED: {exc}", file=sys.stderr)
        return 1
    if arguments.output is not None:
        arguments.output.write_bytes(document)
    else:
        sys.stdout.write(document.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
