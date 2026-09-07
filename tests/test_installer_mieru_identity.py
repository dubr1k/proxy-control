from installer.adapters.mieru import _DefaultMieruRunner


def test_real_mieru_runner_recognizes_existing_named_system_group(monkeypatch):
    runner = _DefaultMieruRunner()
    monkeypatch.setattr(runner, 'capture', lambda argv, **kw: 'mita:x:998:\n')
    assert runner.identity_named('group', 'mita') == 'mita'
    assert runner.identity_named('group', 'other') is None
