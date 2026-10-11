"""Human names distinguish fleet nodes without changing connection credentials."""
import dataclasses
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from panel.protocols.base import AccessArtifact
from panel.subscriptions.models import Manifest, ManifestGrant
from panel.subscriptions.renderers import RENDERERS
from panel.subscriptions.service import SubscriptionService


def feed(protocol="naive", names=("AMS_P", "AMS_Z")):
    grants, artifacts = [], {}
    for index, name in enumerate(names):
        grant = ManifestGrant(
            grant_id=f"grant-{index}", protocol=protocol, node_id=f"node-{index}",
            endpoint_id="default", runtime_username="throne-android", secret_version=1,
            options={}, enabled=True, node_name=name,
        )
        grants.append(grant)
        link = (f"https://user:fake-password@node{index}.example:443" if protocol == "naive" else
                f"mierus://user:fake-password@node{index}.example?profile=old&port=8443&protocol=TCP&mtu=1400")
        artifacts[grant.grant_id] = [AccessArtifact("link", "Connection", "text/uri-list", link)]
    return Manifest("client", "throne-android", 1, grants), artifacts


@pytest.mark.parametrize("protocol,suffix", [("naive", "Naive"), ("mieru", "Mieru · TCP 8443")])
def test_singbox_names_include_node_and_keep_credentials(protocol, suffix):
    manifest, artifacts = feed(protocol)
    outbounds = json.loads(RENDERERS["singbox"].render(manifest, artifacts))["outbounds"]
    assert [out["tag"] for out in outbounds] == [f"AMS_P · {suffix}", f"AMS_Z · {suffix}"]
    assert [out["server"] for out in outbounds] == ["node0.example", "node1.example"]
    assert all(out["username"] == "user" and out["password"] == "fake-password" for out in outbounds)


def test_duplicate_node_names_get_stable_unique_suffixes():
    manifest, artifacts = feed(names=("AMS", "AMS"))
    def render(m):
        return json.loads(RENDERERS["singbox"].render(m, artifacts))["outbounds"]
    first = render(manifest)
    assert len({out["tag"] for out in first}) == 2
    assert all(out["tag"].startswith("AMS · Naive [") for out in first)
    assert {out["server"]: out["tag"] for out in first} == {
        out["server"]: out["tag"] for out in render(dataclasses.replace(manifest, grants=manifest.grants[::-1]))
    }
    # Disabling a sibling must not rename the surviving profile.
    disabled = dataclasses.replace(manifest.grants[1], enabled=False)
    after = render(dataclasses.replace(manifest, grants=[manifest.grants[0], disabled]))
    assert after[0]["tag"] == first[0]["tag"]


def test_clash_group_references_node_qualified_names():
    manifest, artifacts = feed("mieru")
    text = RENDERERS["clash"].render(manifest, artifacts).decode()
    for name in ("AMS_P", "AMS_Z"):
        tag = f"{name} · Mieru · TCP 8443"
        assert f"name: '{tag}'" in text
        assert f"      - '{tag}'" in text


@pytest.mark.parametrize("protocol", ["naive", "mieru"])
def test_raw_links_have_names_without_changing_connection_fields(protocol):
    manifest, artifacts = feed(protocol)
    lines = RENDERERS["raw"].render(manifest, artifacts).decode().splitlines()
    for index, line in enumerate(lines):
        part = urlsplit(line)
        assert part.username == "user" and part.password == "fake-password"
        assert part.hostname == f"node{index}.example"
        expected = ("AMS_P", "AMS_Z")[index] + (" · Naive" if protocol == "naive" else " · Mieru")
        if protocol == "naive":
            assert unquote(part.fragment) == expected
        else:
            assert parse_qs(part.query) == {"profile": [expected], "port": ["8443"], "protocol": ["TCP"], "mtu": ["1400"]}


def test_node_rename_invalidates_etag():
    manifest, _ = feed()
    renamed = dataclasses.replace(manifest.grants[0], node_name="Amsterdam")
    after = dataclasses.replace(manifest, grants=[renamed, manifest.grants[1]])
    assert SubscriptionService.etag(manifest, 2) != SubscriptionService.etag(after, 2)


def test_disabled_grant_node_rename_invalidates_html_etag():
    manifest, artifacts = feed(names=("AMS",))
    disabled = dataclasses.replace(manifest.grants[0], enabled=False)
    before = dataclasses.replace(manifest, grants=[disabled])
    after = dataclasses.replace(before, grants=[dataclasses.replace(disabled, node_name="Paris")])
    assert RENDERERS["html"].render(before, artifacts) != RENDERERS["html"].render(after, artifacts)
    assert SubscriptionService.etag(before, 2) != SubscriptionService.etag(after, 2)


def test_node_name_is_internal_not_a_new_manifest_wire_field():
    manifest, artifacts = feed()
    body = json.loads(RENDERERS["manifest"].render(manifest, artifacts))
    assert body["version"] == 1
    assert "node_name" not in body["grants"][0]
    assert set(body["grants"][0]) == {
        "grant_id", "protocol", "node_id", "endpoint_id", "runtime_username", "secret_version",
        "options", "enabled", "valid_from", "valid_until", "artifacts", "unsupported",
    }


def test_canonically_equivalent_unicode_names_get_unique_suffixes():
    import unicodedata

    manifest, artifacts = feed(names=("Caf\u00e9", "Cafe\u0301"))
    tags = [o["tag"] for o in json.loads(RENDERERS["singbox"].render(manifest, artifacts))["outbounds"]]
    assert len({unicodedata.normalize("NFC", tag) for tag in tags}) == 2
    assert all(tag.startswith("Café · Naive [") for tag in tags)


def test_untrusted_node_names_are_safe_in_all_display_formats():
    manifest, artifacts = feed("mieru", names=("AMS's\n\u202e<script>", " "))
    text = RENDERERS["clash"].render(manifest, artifacts).decode()
    assert "AMS’s <script> · Mieru" in text
    assert "node-1 · Mieru" in text
    page = RENDERERS["html"].render(manifest, artifacts).decode()
    assert "&lt;script&gt;" in page and "<script>" not in page
    assert "\u202e" not in text and "\u202e" not in page
