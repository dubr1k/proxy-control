from urllib.parse import parse_qs
from tests.test_three_xui_api import api_with, ok


def test_panel_does_not_submit_derived_certificate_presence_flags():
    def transport(request):
        method, url, body, headers = request
        if url.endswith('/all'):
            return ok({'success': True, 'obj': {'webPort':2053,'hasCert':False,'hasKey':False}})
        fields=parse_qs(body.decode(),keep_blank_values=True)
        assert not any(k.startswith('has') for k in fields)
        return ok({'success': True, 'obj': {}})
    api=api_with(transport)
    api.configure_panel(web_path='/control/',port=8449,listen='127.0.0.1')
