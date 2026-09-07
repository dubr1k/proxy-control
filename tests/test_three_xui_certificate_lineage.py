import json
from pathlib import Path
from tests.test_installer_three_xui import adapter, RecordingApi, _runtime_action, managed_config
from dataclasses import replace
from installer.three_xui_api import SystemSecrets


def test_subscription_uses_issued_domain_lineage(tmp_path):
    instance=adapter(tmp_path)
    config=managed_config()
    config=replace(config,three_xui=replace(config.three_xui,subscription_domain='sub.example.com'))
    api=RecordingApi()
    captured={}
    def configure(domain, **kwargs):
        captured.update(kwargs)
    api.configure_subscription=configure
    instance.configure_managed(config,api,generator=SystemSecrets(keypair=('private','public')))
    assert captured['certificate']=='/etc/letsencrypt/live/sub.example.com/fullchain.pem'
    assert captured['private_key']=='/etc/letsencrypt/live/sub.example.com/privkey.pem'


def test_subscription_settings_are_followed_by_service_restart(tmp_path):
    instance=adapter(tmp_path)
    config=managed_config()
    config=replace(config,three_xui=replace(config.three_xui,subscription_domain='sub.example.com'))
    api=RecordingApi()
    api.configure_subscription=lambda *args,**kwargs: instance.runner.calls.append(('subscription-configured',))
    instance.api_factory=lambda port,path='/': api
    instance.provision(instance._managed_action(config),password='synthetic-password')
    calls=instance.runner.calls
    configured=calls.index(('subscription-configured',))
    assert any(call==('systemctl','restart','x-ui') for call in calls[configured+1:])


def test_provision_uses_certificate_domain_lineage(tmp_path):
    instance=adapter(tmp_path)
    instance.api_factory=lambda *args: RecordingApi()
    instance.reality_keypair=lambda: ('private', 'public')
    captured={}
    original=instance.runner.bootstrap_session
    def session(**kwargs):
        captured.update(json.loads(Path(kwargs['payload_path']).read_text()))
        return original(**kwargs)
    instance.runner.bootstrap_session=session
    instance.provision(_runtime_action(),password='synthetic-password')
    assert captured['certificate']=='/etc/letsencrypt/live/xui.example.com/fullchain.pem'
    assert captured['private_key']=='/etc/letsencrypt/live/xui.example.com/privkey.pem'
