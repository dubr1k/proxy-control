from urllib.parse import parse_qs

from tests.test_three_xui_api import api_with, ok, config, DeterministicSecrets
from installer.three_xui_api import build_managed_clients, build_managed_inbounds


def test_subscription_has_one_private_id_and_tls_loopback_settings():
    generator = DeterministicSecrets(seed=20)
    inbounds = build_managed_clients(build_managed_inbounds(config(), generator=generator),
        generator=generator, prefix='initial', acceptance=False, subscription_id='private-subscription-id')
    assert all(x.clients[0].settings(x.protocol)['subId'] == 'private-subscription-id' for x in inbounds)
    state = {'webPort': 8443, 'webListen': '127.0.0.1', 'subEnable': False}
    def serve(request):
        method, path, body, _ = request
        assert method == 'POST'
        if path == '/panel/api/setting/all':
            return ok({'success': True, 'obj': state})
        assert path == '/panel/api/setting/update'
        # v3.7.0 AllSetting has no subShowInfo field; Go ignores it.
        state.update({k:v[0] for k,v in parse_qs(body.decode(), keep_blank_values=True).items() if k != 'subShowInfo'})
        return ok({'success': True})
    api = api_with(serve)
    api.configure_subscription('sub.example.com', certificate='/etc/letsencrypt/live/sub/fullchain.pem', private_key='/etc/letsencrypt/live/sub/privkey.pem')
    assert state['subEnable'] == 'true'
    assert state['subListen'] == '127.0.0.1'
    assert state['subPort'] == '2096'
    assert state['subURI'] == 'https://sub.example.com/sub/'
    assert state['subCertFile'] == '/etc/letsencrypt/live/sub/fullchain.pem'
    assert state['webPort'] == '8443'
    assert api.recorded.requests[-1][1] == '/panel/api/setting/all'
