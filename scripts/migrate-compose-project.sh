#!/usr/bin/env bash
# Keep the operator entry point; parsing, preflight and rollback run in the native installer.
set -Eeuo pipefail
RELEASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec bash "$RELEASE_DIR/install.sh" migrate-compose-project "$@"
