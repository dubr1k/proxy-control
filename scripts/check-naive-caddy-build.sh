#!/bin/sh
set -eu
CADDY=${CADDY_BIN:-/usr/local/bin/caddy}
DEFAULT_EXPECTED='v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4='
# The unit runs this from ExecStartPre without the version-agent's environment,
# so an updated build records its pin in a root-owned file the check reads here.
PIN_FILE=${CADDY_VERSION_PIN_FILE:-/etc/proxy-control/caddy-naive.pin}
if [ -n "${EXPECTED_CADDY_VERSION:-}" ]; then
    EXPECTED=$EXPECTED_CADDY_VERSION
elif [ -r "$PIN_FILE" ]; then
    EXPECTED=$(cat "$PIN_FILE")
else
    EXPECTED=$DEFAULT_EXPECTED
fi
actual=$($CADDY version)
if [ "$actual" != "$EXPECTED" ]; then
    printf 'refusing unpinned Caddy build: expected %s, got %s\n' "$EXPECTED" "$actual" >&2
    exit 1
fi
$CADDY list-modules | grep -Fxq 'http.handlers.forward_proxy' || {
    echo 'refusing Caddy build without http.handlers.forward_proxy' >&2
    exit 1
}
