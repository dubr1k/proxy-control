from installer.adapters.mieru import MieruAdapter
from tests.test_installer_mieru import FakeMieruRunner, mieru_action, ROOT


def test_recovery_verifies_nonempty_manager_state_and_new_token_is_32_bytes(tmp_path):
    runner = FakeMieruRunner()
    adapter = MieruAdapter(root=tmp_path, source_dir=ROOT, runner=runner)
    state = tmp_path / adapter.paths.manager_state.lstrip('/')
    state.mkdir(parents=True)
    (state/'state.json').write_text('{}')
    selected = adapter._selection(mieru_action())
    adapter._prepare_manager(selected, 998)
    assert (adapter.paths.state_preparer, 'verify', adapter.paths.manager_state) in runner.calls
    token = (tmp_path / adapter.paths.manager_token.lstrip('/')).read_text('ascii').strip()
    assert len(bytes.fromhex(token)) == 32
