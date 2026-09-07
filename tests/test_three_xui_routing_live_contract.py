import json
from urllib.parse import parse_qs

from tests.test_three_xui_api import api_with, ok, config


def test_warp_writes_and_reads_back_real_xray_setting_contract():
    template = {'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'blocked', 'protocol': 'blackhole'}],
                'routing': {'domainStrategy': 'AsIs', 'rules': [{'ip': ['geoip:private'], 'outboundTag': 'blocked'}]},
                'log': {'loglevel': 'warning'}}
    def serve(request):
        nonlocal template
        method, path, body, _ = request
        if path == '/panel/api/xray/':
            assert method == 'POST'
            return ok({'success': True, 'obj': json.dumps({'xraySetting': template, 'outboundTestUrl': 'https://example.org/'})})
        assert (method, path) == ('POST', '/panel/api/xray/update')
        template = json.loads(parse_qs(body.decode())['xraySetting'][0])
        return ok({'success': True})
    api = api_with(serve)
    api.configure_warp(config(warp=True, warp_domains=('openai.com',)))
    assert template['log'] == {'loglevel': 'warning'}
    assert [x['tag'] for x in template['outbounds']] == ['direct', 'blocked', 'WARP']
    assert template['routing']['rules'][0]['outboundTag'] == 'blocked'
    assert template['routing']['rules'][-2]['domain'] == ['domain:openai.com']
    assert template['routing']['rules'][-1]['outboundTag'] == 'direct'
    assert api.recorded.requests[-1][1] == '/panel/api/xray/'
