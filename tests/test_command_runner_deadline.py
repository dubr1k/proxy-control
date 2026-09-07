import subprocess
import pytest
from installer.audit import CommandRunner


def test_per_call_timeout_cannot_exceed_runner_limit():
    seen=[]
    def execute(argv, *, timeout, max_output):
        seen.append(timeout)
        return subprocess.CompletedProcess(argv,0,'','')
    runner=CommandRunner(timeout=900, executor=execute)
    runner.run(('true',), timeout=0.25)
    runner.run(('true',), timeout=1200)
    assert seen==[0.25,900]
    with pytest.raises(ValueError):
        runner.run(('true',), timeout=0)
