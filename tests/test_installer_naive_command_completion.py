import subprocess

import pytest

from installer.adapters.naive import NaiveAdapter, NaiveError


def test_compose_runs_to_completion_not_through_diagnostic_capture(tmp_path):
    class Runner:
        def capture(self, argv, *, max_chars):
            return 'diagnostic unavailable: TimeoutExpired'

        def run(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, b'', b'container failed readiness')

    adapter = NaiveAdapter(root=tmp_path, runner=Runner())
    with pytest.raises(NaiveError, match='container failed readiness'):
        adapter._compose('up', '-d', '--build', '--wait')
