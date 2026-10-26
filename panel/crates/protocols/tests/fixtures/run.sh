#!/usr/bin/env bash
# Re-records the WP6 goldens on ams-test from the stand copy (see the recorders' docstrings), then
# regenerates the list of transcript tests.
#
# The link/config/QR goldens are recorded with the production interpreter: the panel image's
# Python 3.13.5 (same qrcode, cryptography and pydantic as the stand venv, whose Python 3.12 differs
# in strict base64 and in `str()` of IPv4-mapped IPv6 addresses). The image runs read-only, offline,
# on the stand copy. The transcripts need pytest, so they come from the stand venv.
set -eu
cd "$(dirname "$0")/../../../../.."
PY=/root/dev/proxy-control/.venv/bin/python
FIXTURES=panel/crates/protocols/tests/fixtures
IMAGE=${PANEL_IMAGE:-proxy_panel_by_dubr1k-panel:latest}
docker run --rm --network none --entrypoint python -v "$PWD:/w:ro" -w /w -e PYTHONPATH=/w "$IMAGE" \
    "$FIXTURES/record_goldens.py" > "$FIXTURES/goldens.json"
mapfile -t TESTS < "$FIXTURES/transcript-tests.txt"
TRANSCRIPTS="$FIXTURES/transcripts.json" PYTHONPATH="$FIXTURES:." "$PY" -m pytest -q -p record_transcripts \
    -p no:cacheprovider "${TESTS[@]}"
"$PY" "$FIXTURES/gen_transcript_tests.py"
