from installer.adapters.three_xui import ThreeXuiAdapter
from tests.test_installer_three_xui import adapter, build_release, pinned_action


def test_pinned_debian_unit_is_installed(tmp_path):
    staged=tmp_path/'staged'
    staged.mkdir()
    (staged/'x-ui').write_bytes(b'binary')
    (staged/'x-ui.service.debian').write_text('[Service]\nExecStart=/usr/local/x-ui/x-ui\n')
    instance=ThreeXuiAdapter(root=tmp_path)
    instance._install_tree(staged)
    assert (tmp_path/instance.paths.unit.lstrip('/')).read_bytes() == (staged/'x-ui.service.debian').read_bytes()


def test_system_service_is_never_started_before_private_bootstrap(tmp_path):
    archive=build_release(tmp_path)
    instance=adapter(tmp_path)
    action=pinned_action(tmp_path,archive)
    def provision(*args, **kwargs):
        assert not any(c[:2]==('systemctl','enable') or c[:2]==('systemctl','start') for c in instance.runner.calls)
        return {'inbounds':3}
    instance.provision=provision
    instance.apply(action,instance.prepare(action),archive=archive)
