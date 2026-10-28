"""The image build has its own environment, independent of the caller's Cargo env."""
from pathlib import Path
import shlex

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ('panel', 'naive_manager', 'mieru_manager', 'awg_manager',
          'trusttunnel_manager', 'xray_router_manager', 'mcp_server')


@pytest.mark.parametrize('image', IMAGES)
def test_cargo_image_builds_use_one_job_without_incremental_output(image):
    # Track Docker stage-local ENV, including continued instructions. The final
    # runtime stage must not inherit compiler settings from the build stage.
    text = (ROOT / image / 'Dockerfile').read_text().replace('\\\n', ' ')
    environment = {}
    builds = 0
    final_base = ''
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0].upper() == 'FROM':
            final_base = words[1]
            environment = {}
        elif words[0].upper() == 'ENV':
            for word in words[1:]:
                key, value = word.split('=', 1)
                environment[key] = value
        elif words[0].upper() == 'RUN' and 'cargo' in words:
            builds += 1
            assert environment.get('CARGO_BUILD_JOBS') == '1', image
            assert environment.get('CARGO_INCREMENTAL') == '0', image
    assert builds == 1
    # A named build-stage base would inherit its ENV despite the reset above.
    assert final_base.startswith('debian:') and '@sha256:' in final_base
    assert 'CARGO_BUILD_JOBS' not in environment
    assert 'CARGO_INCREMENTAL' not in environment
