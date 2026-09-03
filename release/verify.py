from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from installer.release import ReleaseError, ReleaseManifest, verify_artifact


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline verification for pinned external release artifacts."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser("manifest", help="validate a release manifest")
    manifest.add_argument("manifest", type=Path)

    artifact = commands.add_parser(
        "artifact", help="verify an artifact against a manifest pin"
    )
    artifact.add_argument("manifest", type=Path)
    artifact.add_argument("name")
    artifact.add_argument("architecture", choices=("amd64", "arm64"))
    artifact.add_argument("artifact", type=Path)
    return parser


def _load_manifest(path: Path) -> ReleaseManifest:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ReleaseError(f"could not read manifest: {path}") from exc
    return ReleaseManifest.from_bytes(data)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = _load_manifest(args.manifest)
        if args.command == "artifact":
            pin = manifest.external_artifact(args.name, args.architecture)
            verify_artifact(args.artifact, pin.sha256)
            print("artifact: ok")
        else:
            print("manifest: ok")
    except ReleaseError as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
