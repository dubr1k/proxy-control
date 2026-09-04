#!/usr/bin/env bash
set -euo pipefail

readonly IMAGE="mtproxy-respq-probe:1.0.0"
readonly DESTINATION="/usr/local/libexec/mtproxy-respq-probe"
readonly TDLIB_VERSION="0.1008066.0"
readonly TDL_VERSION="8.1.0"

owner_id=
if [[ $# -eq 2 && $1 == "--owner-id" && $2 =~ ^[0-9a-f]{32}$ ]]; then
    owner_id=$2
elif [[ $# -ne 0 ]]; then
    printf 'usage: %s [--owner-id HEX32]\n' "${0##*/}" >&2
    exit 2
fi
[[ $(id -u) -eq 0 ]] || {
    printf 'probe install: must run as root\n' >&2
    exit 1
}

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 -c \
    'import json, sys; dependencies = json.load(open(sys.argv[1], encoding="utf-8"))["packages"][""]["dependencies"]; expected = {"prebuilt-tdlib": sys.argv[2], "tdl": sys.argv[3]}; raise SystemExit(0 if dependencies == expected else "locked probe dependency mismatch")' \
    "$source_dir/package-lock.json" "$TDLIB_VERSION" "$TDL_VERSION"
build=(docker build --pull --tag "$IMAGE")
if [[ -n $owner_id ]]; then
    build+=(--label "org.proxy-control.respq-probe.owner=$owner_id")
fi
"${build[@]}" "$source_dir"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0750 "$source_dir/mtproxy-respq-probe" "$DESTINATION"
printf 'probe install: built %s and installed %s\n' "$IMAGE" "$DESTINATION"
