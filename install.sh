#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ ${EUID:-$(id -u)} -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    *) printf 'unsupported architecture: only x86-64 (amd64) is supported\n' >&2; exit 1 ;;
esac
BINARY=$SCRIPT_DIR/installer/bin/linux-$ARCH/proxy-control-installer
[[ -f $BINARY && ! -L $BINARY && -x $BINARY ]] || { printf 'verified release installer binary is missing: %s\n' "$BINARY" >&2; exit 1; }
if (($# == 0)); then set -- wizard; fi
exec "$BINARY" "$@"
