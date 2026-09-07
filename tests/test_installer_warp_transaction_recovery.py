"""Real transaction engine and filesystem; only host commands are simulated."""
import hashlib
import subprocess
import pytest
from installer.adapters import warp as warp_module
from installer.planner import InstallPlan, ReleaseIdentity
from installer.transaction import TransactionEngine, TransactionStore, OwnershipError
from installer.config import parse_config
from installer.model import ThreeXuiConfig
from installer.planner import AuditFacts
from installer.adapters.warp import WarpAdapter
from installer.adapters.naive import NaiveAdapter
from installer.adapters.mieru import MieruAdapter
from installer.three_xui_api import warp_routing
from tests.test_installer_config import FULL_MANAGED_TOML


def test_new_install_uses_45000_for_every_warp_consumer():
    config = parse_config(FULL_MANAGED_TOML.replace('warp = false', 'warp = true'))
    assert ThreeXuiConfig(mode=config.three_xui.mode).warp_port == 45000
    assert config.three_xui.warp_port == 45000
    assert WarpAdapter().plan(config, AuditFacts())[0].mutations == ('port=45000',)
    for adapter in (NaiveAdapter(), MieruAdapter()):
        selected = adapter._selection(adapter.plan(config, AuditFacts())[0])
        assert selected['warp_port'] == 45000
    from dataclasses import replace
    routing_config = replace(config, three_xui=replace(config.three_xui, warp_domains=('example.org',)))
    policy = warp_routing(routing_config, existing_rules=[])
    assert policy['outbounds'][0]['settings']['servers'][0]['port'] == 45000
    from installer.adapters.three_xui import ThreeXuiAdapter
    xui = ThreeXuiAdapter()
    action = next(a for a in xui.plan(routing_config, AuditFacts()) if a.id == 'three_xui.runtime')
    old_action = replace(action, mutations=tuple(m for m in action.mutations if not m.startswith('warp-port=')))
    assert xui._managed_config(old_action).three_xui.warp_port == 45000




class HostCommands:
    """External command seam: no command is ever executed on the host."""
    def __init__(self):
        self.connected = False
        self.installed = False
        self.configured = True
        self.interrupt_install = False
        self.calls = []

    def run(self, argv, **kwargs):
        argv = tuple(argv)
        self.calls.append(argv)
        output = ''
        rc = 0
        if argv[0] == 'dpkg-query':
            rc = 0 if self.installed else 1
            output = warp_module.VERSION if self.installed else ''
            if '${db:Status-Status}' in argv[2]:
                output = 'installed' if self.configured else 'unpacked'
        elif argv[:2] == ('apt-get', 'install'):
            self.installed = True
            if self.interrupt_install:
                self.configured = False
                self.interrupt_install = False
                raise PowerLoss()
        elif argv[:2] == ('dpkg', '--configure'):
            self.configured = True
        elif argv[:2] == ('apt-get', 'purge'):
            self.installed = False
        elif argv[:2] == ('systemctl', 'is-active'):
            output = 'active'
        elif argv[:2] == ('systemctl', 'is-enabled'):
            output = 'enabled'
        elif argv[0] == 'ss':
            output = 'LISTEN 0 128 127.0.0.1:45000 0.0.0.0:* users:(("warp-svc",pid=99,fd=1))' if self.connected else ''
        elif argv == ('warp-cli', '--accept-tos', 'connect'):
            self.connected = True
        elif argv[0] == 'curl':
            output = ('ip=198.51.100.2\nwarp=on\n' if '--socks5-hostname' in argv
                      else 'ip=192.0.2.1\nwarp=off\n')
        else:
            output = 'Status update: Connected'
        return subprocess.CompletedProcess(argv, rc, output, '')


def transaction(tmp_path, monkeypatch):
    runner = HostCommands()
    adapter = WarpAdapter(root=tmp_path, runner=runner)
    key_bytes = b'synthetic signing key'
    monkeypatch.setattr(warp_module, 'KEY_SHA256', hashlib.sha256(key_bytes).hexdigest())
    def acquire():
        for relative, data in ((warp_module.KEY_PATH, key_bytes), (warp_module.REPO_PATH, warp_module.REPO)):
            path = tmp_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return tmp_path / 'var/lib/proxy-control/warp/cloudflare-warp.deb'
    monkeypatch.setattr(adapter, '_prepare_package', acquire)
    config = parse_config(FULL_MANAGED_TOML.replace('warp = false', 'warp = true'))
    plan = InstallPlan(config=config.canonical_dict(), facts=AuditFacts(),
        release=ReleaseIdentity(tag='test', commit='test', manifest_sha256='a'*64),
        adapter_order=('warp',), adapter_dependencies={'warp': ()},
        actions=adapter.plan(config, AuditFacts()))
    store = TransactionStore(tmp_path)
    engine = TransactionEngine(store, {'warp': adapter})
    return runner, adapter, plan, store, engine


def test_engine_rejects_marker_drift_on_repeat_install(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    state = engine.apply(plan, plan.digest)
    assert state.status == 'active'
    (tmp_path / 'var/lib/proxy-control/warp/owner').write_text('foreign')
    runner.calls.clear()
    with pytest.raises(OwnershipError):
        engine.apply(plan, plan.digest)
    assert not runner.calls


def test_failed_purge_preserves_proof_for_engine_resume(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    original = runner.run
    def incomplete_purge(argv):
        if tuple(argv[:2]) == ('apt-get', 'purge'):
            return subprocess.CompletedProcess(argv, 0, '', '')
        return original(argv)
    monkeypatch.setattr(runner, 'run', incomplete_purge)
    with pytest.raises(warp_module.WarpError, match='package remains'):
        engine.uninstall(purge_data=False)
    assert (tmp_path / 'var/lib/proxy-control/warp/owner').exists()
    assert (tmp_path / warp_module.REPO_PATH).exists()
    monkeypatch.setattr(runner, 'run', original)
    assert engine.resume().status == 'uninstalled'


def test_resume_purge_when_unit_was_already_removed(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    original = runner.run
    def removed_unit(argv):
        if tuple(argv[:3]) == ('systemctl', 'disable', '--now'):
            return subprocess.CompletedProcess(argv, 1, '', 'unit does not exist')
        if tuple(argv[:2]) == ('systemctl', 'show'):
            return subprocess.CompletedProcess(argv, 0, 'LoadState=not-found\nActiveState=inactive\n', '')
        return original(argv)
    monkeypatch.setattr(runner, 'run', removed_unit)
    assert engine.uninstall(purge_data=False).status == 'uninstalled'
    assert not runner.installed


def test_egress_probe_overrides_inherited_no_proxy(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    command = next(c for c in runner.calls if '--socks5-hostname' in c)
    assert '--noproxy' in command
    assert command[command.index('--noproxy') + 1] == ''


@pytest.mark.parametrize('resume_install', [True, False])
def test_engine_recovers_sigkill_before_owner_replace(tmp_path, monkeypatch, resume_install):
    import os
    import signal
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    replace = os.replace
    pid = os.fork()
    if pid == 0:
        def kill_before_owner(src, dst):
            if str(dst).endswith('/warp/owner'):
                os.kill(os.getpid(), signal.SIGKILL)
            return replace(src, dst)
        os.replace = kill_before_owner
        engine.apply(plan, plan.digest)
        os._exit(70)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == -signal.SIGKILL
    assert store.read_state().status == 'applying'
    if resume_install:
        assert engine.resume().status == 'active'
        assert engine.uninstall(purge_data=False).status == 'uninstalled'
    else:
        runner.connected = True  # The proxy port became occupied after the crash.
        with pytest.raises(warp_module.WarpError, match='port is occupied'):
            engine.resume()
        assert store.read_state().status == 'rolled_back'
        assert not (tmp_path / 'var/lib/proxy-control/warp').exists()


def test_registration_retries_transient_daemon_with_bounded_calls(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    original=runner.run
    failures=[]
    deadlines=[]
    def run(argv, **kwargs):
        if argv[0]=='warp-cli':
            deadlines.append(kwargs.get('timeout', 999))
        if tuple(argv[-2:]) in {('registration','show'), ('registration','new')} and len(failures)<2:
            failures.append(tuple(argv))
            return subprocess.CompletedProcess(argv,1,'','daemon unavailable')
        return original(argv, **kwargs)
    monkeypatch.setattr(runner,'run',run)
    monkeypatch.setattr(warp_module.time,'sleep',lambda _: None)
    assert engine.apply(plan,plan.digest).status=='active'
    assert len(failures)==2
    assert all(0 < t <= 5 for t in deadlines)


class PowerLoss(BaseException):
    pass


def test_engine_resumes_cleanup_after_owner_unlink(tmp_path, monkeypatch):
    import os
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    unlink = os.unlink
    fired = False
    def interrupt(path, *args, **kwargs):
        nonlocal fired
        unlink(path, *args, **kwargs)
        if str(path).split('/')[-1] == 'owner' and not fired:
            fired = True
            raise PowerLoss()
    with monkeypatch.context() as m:
        m.setattr(os, 'unlink', interrupt)
        with pytest.raises(PowerLoss):
            engine.uninstall(purge_data=False)
    assert store.read_state().status == 'uninstalling'
    assert engine.resume().status == 'uninstalled'
    assert not (tmp_path / 'var/lib/proxy-control/warp').exists()


def test_cleanup_fsyncs_removed_entries_before_engine_completion(tmp_path, monkeypatch):
    import installer.transaction as tx
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    synced = []
    real_sync = tx.fsync_directory
    def record(path):
        synced.append(path)
        real_sync(path)
    monkeypatch.setattr(tx, 'fsync_directory', record)
    assert engine.uninstall(purge_data=False).status == 'uninstalled'
    assert tmp_path / 'etc/apt/sources.list.d' in synced
    assert tmp_path / 'usr/share/keyrings' in synced
    assert tmp_path / 'var/lib/proxy-control' in synced


def test_engine_completes_unpacked_package_on_resume(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    runner.interrupt_install = True
    with pytest.raises(PowerLoss):
        engine.apply(plan, plan.digest)
    assert store.read_state().status == 'applying'
    runner.calls.clear()
    assert engine.resume().status == 'active'
    assert runner.configured
    assert runner.calls.index(('dpkg', '--configure', 'cloudflare-warp')) < runner.calls.index(('systemctl', 'enable', '--now', 'warp-svc'))


@pytest.mark.parametrize('relative', ['var/lib/cloudflare-warp', warp_module.KEY_PATH, warp_module.REPO_PATH])
def test_apply_refuses_foreign_state_appearing_after_prepare(tmp_path, monkeypatch, relative):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    action = plan.actions[0]
    checkpoint = adapter.prepare(action)
    foreign = tmp_path / relative
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_bytes(b'foreign')
    runner.calls.clear()
    with pytest.raises(warp_module.WarpError):
        adapter.apply(action, checkpoint)
    assert foreign.read_bytes() == b'foreign'
    assert not any(c[0] in {'apt-get', 'systemctl', 'warp-cli'} for c in runner.calls)


@pytest.mark.parametrize('listener', [
    'LISTEN 0 128 127.0.0.1:45000 0.0.0.0:* users:(("foreign",pid=99,fd=1))',
    'LISTEN 0 128 0.0.0.0:45000 0.0.0.0:* users:(("warp-svc",pid=99,fd=1))',
])
def test_verify_rejects_foreign_or_public_socks_listener(tmp_path, monkeypatch, listener):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    original = runner.run
    def run(argv, **kwargs):
        if argv[0] == 'ss':
            return subprocess.CompletedProcess(argv, 0, listener, '')
        return original(argv)
    monkeypatch.setattr(runner, 'run', run)
    with pytest.raises(warp_module.WarpError):
        adapter.verify(plan.actions[0])


def test_apply_waits_for_transient_daemon_status(tmp_path, monkeypatch):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    original = runner.run
    attempts = 0
    def run(argv, **kwargs):
        nonlocal attempts
        if tuple(argv) == ('warp-cli', '--accept-tos', 'status'):
            attempts += 1
            if attempts == 1:
                return subprocess.CompletedProcess(argv, 1, '', 'daemon is starting')
        return original(argv)
    monkeypatch.setattr(runner, 'run', run)
    monkeypatch.setattr(warp_module.time, 'sleep', lambda _: None)
    assert engine.apply(plan, plan.digest).status == 'active'
    assert attempts >= 2


@pytest.mark.parametrize('method', ['repair', 'reconcile_apply'])
def test_repair_and_resume_reject_repository_drift_before_mutation(tmp_path, monkeypatch, method):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    state = engine.apply(plan, plan.digest)
    checkpoint = dict(state.checkpoints[0].data)
    (tmp_path / warp_module.REPO_PATH).write_bytes(b'foreign')
    runner.calls.clear()
    with pytest.raises(warp_module.WarpError):
        getattr(adapter, method)(plan.actions[0], checkpoint)
    assert not any(c[0] in {'apt-get', 'systemctl', 'warp-cli'} for c in runner.calls)


@pytest.mark.parametrize('check', ['is-active', 'is-enabled'])
def test_verify_requires_active_and_boot_enabled_service(tmp_path, monkeypatch, check):
    runner, adapter, plan, store, engine = transaction(tmp_path, monkeypatch)
    engine.apply(plan, plan.digest)
    original = runner.run
    def run(argv, **kwargs):
        if tuple(argv[:2]) == ('systemctl', check):
            return subprocess.CompletedProcess(argv, 1, 'inactive', '')
        return original(argv)
    monkeypatch.setattr(runner, 'run', run)
    with pytest.raises(warp_module.WarpError):
        adapter.verify(plan.actions[0])
