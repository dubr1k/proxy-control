import subprocess
import pytest
from installer.adapters.mieru import MieruAdapter, MieruError
from installer.planner import AuditFacts
from tests.test_installer_mieru import full_config


def test_generated_manager_token_is_valid_http_text(tmp_path, monkeypatch):
    monkeypatch.setattr('secrets.token_bytes', lambda n: b'\xff' * n)
    class Runner:
        def run(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, '', '')
    adapter = MieruAdapter(root=tmp_path, runner=Runner())
    action = adapter.plan(full_config(), AuditFacts())[0]
    adapter._prepare_manager(adapter._selection(action), 321)
    token = (tmp_path / adapter.paths.manager_token.lstrip('/')).read_text(encoding='ascii').strip()
    assert len(token) >= 64
    assert token.isalnum()


def test_compose_failure_retains_bounded_sanitized_diagnostics(tmp_path):
    class Runner:
        def run(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, '', 'long build progress '*500)
        def capture(self, argv, *, max_chars):
            if 'inspect' in argv:
                return 'restarting exit=1 oom=false health=unhealthy'
            if 'logs' in argv:
                return 'PermissionError: permission denied /run/mieru\nValueError: PLAIN-SENSITIVE-MATERIAL\npassword=DO-NOT-LEAK Bearer DO-NOT-LEAK\n' + 'x'*10000
            return 'a'*64
    adapter = MieruAdapter(root=tmp_path, runner=Runner())
    with pytest.raises(MieruError) as error:
        adapter._compose('up', '-d', '--build', '--wait')
    message = str(error.value)
    assert 'PermissionError' in message
    assert 'exit=1' in message
    assert 'DO-NOT-LEAK' not in message
    assert 'PLAIN-SENSITIVE-MATERIAL' not in message
    assert len(message) <= 3200
