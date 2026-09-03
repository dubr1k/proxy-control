#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ ${EUID:-$(id -u)} -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
if [[ $# -eq 0 ]]; then
    exec env PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m installer.cli wizard
fi
exec env PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 -m installer.cli "$@"
