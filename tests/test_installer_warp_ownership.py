import subprocess
import pytest
from installer.adapters.warp import WarpAdapter, WarpError, REPO_PATH
from installer.config import parse_config
from installer.planner import AuditFacts
from tests.test_installer_config import FULL_MANAGED_TOML


@pytest.mark.parametrize('tamper', ['repository', 'missing-marker'])
def test_warp_rollback_checks_all_ownership_before_any_mutation(tmp_path, tamper):
    commands=[]
    class Runner:
        def run(self, argv):
            commands.append(tuple(argv))
            return subprocess.CompletedProcess(argv, 1 if tamper == 'missing-marker' else 0, '2026.7.1377.0', '')
    adapter=WarpAdapter(root=tmp_path, runner=Runner())
    action=adapter.plan(parse_config(FULL_MANAGED_TOML.replace('warp = false','warp = true')), AuditFacts())[0]
    checkpoint={'marker':'a'*32,'ownership':{}}
    marker=tmp_path/'var/lib/proxy-control/warp/owner'
    marker.parent.mkdir(parents=True)
    if tamper!='missing-marker':
        marker.write_text('a'*32)
    repo=tmp_path/REPO_PATH
    repo.parent.mkdir(parents=True)
    repo.write_text('foreign')
    with pytest.raises(WarpError):
        adapter.rollback(action,checkpoint)
    assert not any(c[0] in {'apt-get','systemctl'} for c in commands)
