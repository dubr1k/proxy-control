#!/usr/bin/env bash
set -euo pipefail

readonly IMAGE="mtproxy-respq-probe:1.0.0"
readonly DESTINATION="/usr/local/libexec/mtproxy-respq-probe"

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
# Core validates the exact locked dependencies in Rust before invoking this script.
# npm ci in the image verifies package-lock integrity; no host interpreter is needed.
# The image carries the digest of the sources it was built from. Without it an
# image built from older sources looks current, and a fix that shipped in a
# release never reaches the container that runs it.
sources_sha256=$(cat "$source_dir/src/index.cjs" "$source_dir/Dockerfile" \
    "$source_dir/package-lock.json" | sha256sum | cut -d" " -f1)
build=(docker build --pull --tag "$IMAGE"
    --label "org.proxy-control.respq-probe.sources=$sources_sha256")
if [[ -n $owner_id ]]; then
    build+=(--label "org.proxy-control.respq-probe.owner=$owner_id")
fi
"${build[@]}" "$source_dir"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0750 "$source_dir/mtproxy-respq-probe" "$DESTINATION"
printf 'probe install: built %s and installed %s\n' "$IMAGE" "$DESTINATION"
