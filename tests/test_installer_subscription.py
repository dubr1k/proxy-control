from installer.config import parse_config, render_config
from installer.adapters.three_xui import ThreeXuiAdapter
from installer.adapters.nginx import _certificate_groups
from tests.test_installer_config import FULL_MANAGED_TOML


def test_subscription_and_warp_selection_survive_planning():
    text = FULL_MANAGED_TOML.replace('warp = false', 'subscription_domain = "sub.example.com"\nwarp = true\nwarp_port = 41000').replace('warp_domains = []', 'warp_domains = ["geosite:openai", "example.org"]')
    config = parse_config(text)
    assert parse_config(render_config(config)) == config
    assert 'sub.example.com' in config.required_domains()
    groups = _certificate_groups(config)
    assert ('three-xui-subscription', 'sub.example.com', ('sub.example.com',)) in groups
    adapter = ThreeXuiAdapter()
    assert ('sub.example.com', '127.0.0.1:2096') in adapter._managed_routes(config)
    restored = adapter._managed_config(adapter._managed_action(config))
    assert restored.three_xui == config.three_xui


def test_managed_provision_actually_applies_warp_and_subscription(tmp_path):
    from dataclasses import replace
    from tests.test_three_xui_api import DeterministicSecrets
    config = parse_config(FULL_MANAGED_TOML)
    config = replace(config, three_xui=replace(config.three_xui, warp=True, warp_domains=('example.org',), subscription_domain='sub.example.com'))
    class Api:
        called = []
        def add_inbound(self, inbound):
            return len(self.called) + 1
        def replace_clients(self, identifier, inbound):
            pass
        def effective_config(self):
            return {'client_emails': []}
        def configure_warp(self, selected):
            self.called.append('warp')
        def configure_subscription(self, domain, **kwargs):
            assert domain == 'sub.example.com'
            self.called.append('subscription')
    adapter = ThreeXuiAdapter(root=tmp_path)
    api = Api()
    adapter.configure_managed(config, api, generator=DeterministicSecrets(seed=28))
    assert api.called == ['warp', 'subscription']
    output = tmp_path / 'var/lib/proxy-control/three-xui/subscription-url'
    assert output.read_text().startswith('https://sub.example.com/sub/')
    assert output.stat().st_mode & 0o777 == 0o600
