#!/bin/sh
# Regenerates only the Unicode tables with external CPython 3.13 on ams-test.
# model.json is a frozen Python-application oracle; its recorder was retired at cutover.
#
#     sh panel/crates/model/tests/fixtures/generators/run.sh
set -eu
python=${PYTHON:-python3.13}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
"$python" -I panel/crates/model/tests/fixtures/generators/gen_tables.py "$out/tables.rs"
cp "$out/tables.rs" panel/crates/model/src/routing/tables.rs
