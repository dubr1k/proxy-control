#!/usr/bin/env bash
# Parse-check the panel UI sources.
#
# `node --check file.js` parses the file as CommonJS, so every ES module in
# panel/static rejects with "Cannot use import statement outside a module".
# Node decides by extension, so each module is copied to a .mjs name and checked
# there. This checks the whole UI, not just the app.js entry point.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

status=0
for js in "$ROOT"/panel/static/app.js "$ROOT"/panel/static/js/*.js; do
  test -f "$js" || continue
  name=$(basename "$js" .js)
  cp "$js" "$tmp/$name.mjs"
  node --check "$tmp/$name.mjs" || { echo "syntax error: $js" >&2; status=1; }
done

test "$status" -eq 0 && echo "panel UI modules parse: OK"
exit "$status"
