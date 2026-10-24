"""The «На чём клиент?» catalogue: one source for the chooser (and the end-user page), derived from
the compatibility matrix and the link variants, with every deep link traceable to a vendor source."""

from __future__ import annotations

import re
from pathlib import Path

from panel.subscription_routes import SHARE_VARIANTS
from panel.subscriptions import apps
from panel.subscriptions.compatibility import MATRIX

SOURCE = Path(apps.__file__).read_text()
KNOWN_SCHEMES = {"karing", "hiddify", "sing-box", "clash"}


def by_id():
    return {app["id"]: app for app in apps.catalogue()["apps"]}


def test_every_app_maps_to_one_existing_link_variant_and_matrix_column():
    for app in apps.APPS:
        assert app["variant"] in SHARE_VARIANTS, app["id"]
        assert app["matrix"] in MATRIX["naive"], app["id"]
        assert set(app["delivers"]) <= set(apps.SUBSCRIPTION_PROTOCOLS), app["id"]
        assert set(app["platforms"]) <= {key for key, _ in apps.PLATFORMS}, app["id"]
    assert len({app["id"] for app in apps.APPS}) == len(apps.APPS)
    assert {key for key, _ in apps.PLATFORMS} == {"ios", "android", "windows", "macos", "linux"}


def test_what_an_app_gets_is_derived_from_the_matrix_and_the_variant():
    found = by_id()
    # works = delivered by the variant and proven; unverified = delivered, not proven; no = the rest.
    assert found["karing"]["protocols"] == {"naive": "works", "mieru": "works", "trusttunnel": "no"}
    assert found["hiddify"]["protocols"] == {"naive": "no", "mieru": "no", "trusttunnel": "pending"}  # not in the app's releases yet
    assert found["singbox"]["protocols"] == {"naive": "works", "mieru": "no", "trusttunnel": "no"}
    assert found["flclash"]["protocols"] == {"naive": "no", "mieru": "works", "trusttunnel": "works"}
    assert found["throne"]["protocols"]["trusttunnel"] == "unverified"
    # AmneziaWG and MTProxy are not subscription protocols: the chooser never mentions them.
    assert all(set(app["protocols"]) == {"naive", "mieru", "trusttunnel"} for app in found.values())


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


def test_download_links_are_https():
    for app in apps.catalogue()["apps"]:
        assert app["downloads"], app["id"]
        assert all(item["url"].startswith("https://") and item["label"] for item in app["downloads"]), app["id"]


def test_the_catalogue_is_free_of_ui_code():
    assert "innerHTML" not in SOURCE and "document" not in SOURCE
