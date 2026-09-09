from dataclasses import replace

import pytest

from installer.config import parse_config
from installer.planner import AuditFacts, adapters_for
from tests.test_installer_config import FULL_MANAGED_TOML


def test_warp_is_owned_before_consumers_and_requires_real_egress(tmp_path):
    from installer.adapters.warp import WarpAdapter, WarpError
    config = parse_config(FULL_MANAGED_TOML)
    config = replace(config, three_xui=replace(config.three_xui, warp=True, warp_domains=('2ip.ru',)))
    adapter = WarpAdapter(root=tmp_path)
    action = adapter.plan(config, AuditFacts())[0]
    assert action.id == 'warp.runtime'
    names = [a.name for a in adapters_for(config, warp=adapter)]
    assert names.index('warp') < names.index('naive')
    assert names.index('warp') < names.index('three_xui')
    assert adapter.validate_egress('ip=192.0.2.1\nwarp=off\n', 'ip=198.51.100.2\nwarp=on\n')
    with pytest.raises(WarpError):
        adapter.validate_egress('ip=192.0.2.1\nwarp=off\n', 'ip=192.0.2.1\nwarp=off\n')


def test_warp_owned_lifecycle_and_foreign_install_refusal(tmp_path):
    import subprocess
    from installer.adapters.warp import WarpAdapter, WarpError

    class Runner:
        installed = False
        commands = []
        def run(self, argv, **kwargs):
            self.commands.append(tuple(argv))
            if argv[:2] in {('systemctl', 'is-active'), ('systemctl', 'is-enabled')}:
                return subprocess.CompletedProcess(argv, 0, 'active' if argv[1] == 'is-active' else 'enabled', '')
            if argv[0] == 'ss':
                text = 'LISTEN 0 128 127.0.0.1:40000 0.0.0.0:* users:(("warp-svc",pid=99,fd=1))' if self.installed else ''
                return subprocess.CompletedProcess(argv, 0, text, '')
            if argv[0] == 'dpkg-query':
                value = 'installed' if '${db:Status-Status}' in argv[2] else '2026.7.1377.0'
                return subprocess.CompletedProcess(argv, 0 if self.installed else 1,
                    value if self.installed else '', '')
            if argv[:2] == ('apt-get', 'install'):
                self.installed = True
            if argv[:2] == ('apt-get', 'purge'):
                self.installed = False
            if argv[0] == 'curl' and '--socks5-hostname' in argv:
                return subprocess.CompletedProcess(argv, 0, 'ip=198.51.100.2\nwarp=on\n', '')
            if argv[0] == 'curl':
                return subprocess.CompletedProcess(argv, 0, 'ip=192.0.2.1\nwarp=off\n', '')
            return subprocess.CompletedProcess(argv, 0, 'Status update: Connected', '')

    runner = Runner()
    adapter = WarpAdapter(root=tmp_path, runner=runner)
    config = parse_config(FULL_MANAGED_TOML.replace('warp = false', 'warp = true'))
    action = adapter.plan(config, AuditFacts())[0]
    # Network package acquisition is the external seam; lifecycle stays real.
    adapter._prepare_package = lambda: tmp_path / 'cloudflare-warp.deb'
    checkpoint = adapter.prepare(action)
    applied = adapter.apply(action, checkpoint)
    assert adapter.verify(action).success
    commands = runner.commands
    mode_index = commands.index(('warp-cli', '--accept-tos', 'mode', 'proxy'))
    assert mode_index < commands.index(('warp-cli', '--accept-tos', 'connect'))
    assert ('warp-cli', '--accept-tos', 'proxy', 'port', '40000') in commands
    assert adapter.rollback(action, applied).success
    assert not runner.installed
    runner.installed = True
    with pytest.raises(WarpError, match='foreign'):
        adapter.prepare(action)
