#!/bin/sh
# Regenerates the goldens and the Unicode tables of panel-model with the panel image's interpreter
# (CPython 3.13.5, pydantic 2.13.4, FastAPI 0.142.2). Run from the repository root on ams-test:
#
#     sh panel/crates/model/tests/fixtures/generators/run.sh
set -eu
image=${PANEL_IMAGE:-proxy_panel_by_dubr1k-panel:latest}
out=$(mktemp -d)
chmod 0777 "$out"
docker run --rm --network none -v "$PWD:/src:ro" -v "$out:/out" -e PYTHONPATH=/src --entrypoint python "$image" \
    /src/panel/crates/model/tests/fixtures/generators/gen_model.py /out
docker run --rm --network none -v "$PWD:/src:ro" -v "$out:/out" --entrypoint python "$image" -I \
    /src/panel/crates/model/tests/fixtures/generators/gen_tables.py /out/tables.rs
cp "$out/model.json" panel/crates/model/tests/fixtures/model.json
cp "$out/tables.rs" panel/crates/model/src/routing/tables.rs
rm -rf "$out"
