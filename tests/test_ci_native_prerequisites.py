"""CI must supply native test dependencies in the environment that runs tests."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_privileged_external_suite_keeps_rust_toolchain_and_real_installer():
    workflow = (ROOT / '.github/workflows/test.yml').read_text()
    command = re.search(r'sudo env PANEL_IMPL=rust.*?\.venv/bin/python - <<', workflow, re.S)
    assert command is not None
    env = command.group()
    for assignment in ('PATH="$PATH"', 'HOME="$HOME"', 'CARGO_HOME="$HOME/.cargo"',
                       'RUSTUP_HOME="$HOME/.rustup"',
                       'PROXY_CONTROL_TEST_INSTALLER="$PWD/installer/bin/linux-amd64/proxy-control-installer"'):
        assert assignment in env, f'privileged suite loses {assignment}'


def test_host_check_stage_has_real_consumer_dependencies_only_in_check_stage():
    dockerfile = (ROOT / 'release/Dockerfile.host-binaries').read_text()
    check = dockerfile.split('FROM builder AS check\n', 1)[1].split('FROM scratch AS checked', 1)[0]
    command = re.search(r'apk add --no-cache ([^\n;]+)', check)
    assert command is not None, 'host check lacks its external consumer prerequisites'
    assert {'python3', 'openssl', 'nginx', 'nginx-mod-stream'} <= set(command.group(1).split())
    assert 'apk add' not in dockerfile.split('FROM builder AS check\n', 1)[0]
    assert 'apk add' not in dockerfile.split('FROM builder AS build\n', 1)[1]


def test_pinned_builder_respects_single_heavy_slot():
    dockerfile = (ROOT / 'release/Dockerfile.host-binaries').read_text()
    assert 'CARGO_BUILD_JOBS=1' in dockerfile.split('FROM builder AS check', 1)[0]
