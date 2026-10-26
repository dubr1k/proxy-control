#!/usr/bin/env bash
# Verified-release entry point. The native installer owns transition ordering and rollback.
set -Eeuo pipefail
RELEASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec bash "$RELEASE_DIR/install.sh" update-host "$@"
