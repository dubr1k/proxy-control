"""The «На чём клиент?» catalogue: one source for the chooser (and the end-user page), derived from
the compatibility matrix and the link variants, with every deep link traceable to a vendor source."""

from __future__ import annotations

import re
from pathlib import Path


from panel.subscriptions import apps


SOURCE = Path(apps.__file__).read_text()
KNOWN_SCHEMES = {"karing", "hiddify", "sing-box", "clash"}


def by_id():
    return {app["id"]: app for app in apps.catalogue()["apps"]}








def test_deep_links_use_known_schemes_each_with_a_source_next_to_it():
    for app in apps.APPS:
        template = app["deeplink"]
        if template is None:
            continue
        scheme = template.split("://", 1)[0]
        assert scheme in KNOWN_SCHEMES, app["id"]
        assert "{url" in template, app["id"]
        # the line above the template names the vendor's page or repository the scheme comes from
        index = SOURCE.index(f'"deeplink": "{template}"')
        assert re.search(r"# https://\S+", SOURCE[SOURCE.rindex("\n", 0, SOURCE.rindex("\n", 0, index)) : index]), app["id"]
    # An app without a verified scheme has no button.
    found = by_id()
    assert found["throne"]["deeplink"] is None and found["clash-verge-rev"]["deeplink"] is None and found["clashmi"]["deeplink"] is None
    assert found["hiddify"]["deeplink"] == "hiddify://import/{url}#{name_enc}"
    assert found["karing"]["deeplink"] == "karing://install-config?url={url_enc}&name={name_enc}"
    assert found["singbox"]["deeplink"] == "sing-box://import-remote-profile?url={url_enc}#{name_enc}"
    assert found["flclash"]["deeplink"] == "clash://install-config?url={url_enc}"






