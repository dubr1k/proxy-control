#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec "$SCRIPT_DIR/../installer/bin/linux-amd64/proxy-control-installer" prepare-mieru-token "$@"
